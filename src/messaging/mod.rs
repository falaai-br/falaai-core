//! Mensagens guardadas no banco local: as recebidas ([`Inbox`]), os recibos recebidos e as que
//! esperam envio ([`outbox`]); o formato do que vai dentro do selo fica em [`content`].
//!
//! Uma mensagem recebida é gravada dentro da transação que a decifra (o `deliver` de
//! [`crate::protocol::Sessions::decrypt`]): ratchet e mensagem avançam juntos ou nenhum. Assim
//! o que a Notification Service Extension do iOS decifra fica no banco para o app, que não
//! recebe o evento dela.
//!
//! A entrega é at-least-once e quem envia reenvia quando não vê o `SendAck`, então a mesma
//! mensagem pode chegar mais de uma vez. O mesmo envelope (mesmo `seq`) o ratchet recusa; um
//! reenvio, cifrado de novo, o ratchet aceita, e quem o reconhece é o `client_message_id` gravado
//! junto com a mensagem.
//!
//! Recibos de entrega e de leitura seguem a mesma regra: gravados na transação que os decifra
//! e deduplicados pelo `client_message_id` do envelope. O indicador de digitação não é gravado
//! em lugar nenhum: vira evento se houver quem ouça, ou some.

pub(crate) mod content;
pub(crate) mod outbox;

use std::sync::Arc;

use rusqlite::types::{FromSqlError, Type};
use rusqlite::{OptionalExtension, params};

use self::content::{ReceiptType, join_ids, split_ids};
use self::outbox::{CLIENT_MESSAGE_ID_LEN, ClientMessageId};
use crate::protocol::{Address, Plaintext};
use crate::storage::{Database, StorageError};

/// Mensagem recebida e gravada. Sem `Debug`: o texto claro não pode ir para log.
pub(crate) struct InboxMessage {
    /// Cursor: cresce na ordem em que as mensagens foram gravadas, por qualquer processo.
    pub(crate) id: i64,
    pub(crate) from: Address,
    /// Instante em que o servidor recebeu o envelope, em milissegundos desde a época Unix.
    pub(crate) server_timestamp: u64,
    pub(crate) body: Plaintext,
    /// A chave de identidade do remetente mudou ao decifrar esta mensagem.
    pub(crate) identity_changed: bool,
}

/// Recibo recebido e gravado: o remetente confirma que as mensagens `client_message_ids`, que
/// este aparelho enviou a ele, foram entregues ou lidas.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InboxReceipt {
    /// Cursor, como [`InboxMessage::id`]; sequência própria, separada da das mensagens.
    pub(crate) id: i64,
    pub(crate) from: Address,
    pub(crate) kind: ReceiptType,
    pub(crate) client_message_ids: Vec<ClientMessageId>,
    /// Instante em que o servidor recebeu o envelope, em milissegundos desde a época Unix.
    pub(crate) server_timestamp: u64,
}

/// Mensagens recebidas, sobre o banco local. Clonar só copia o handle da conexão.
#[derive(Clone)]
pub(crate) struct Inbox {
    db: Arc<Database>,
}

impl Inbox {
    /// Caixa de entrada sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Grava a mensagem que `from` enviou com `client_message_id`, com a marca de que a
    /// identidade dele mudou nela, e devolve o id dela, ou `None` se `from` já tinha enviado uma
    /// mensagem com esse `client_message_id` (um reenvio), sem gravar nada. Um
    /// `client_message_id` vazio não deduplica. Dentro da transação de [`Database::begin`], só
    /// vale se ela for confirmada.
    pub(crate) fn record(
        &self,
        from: &Address,
        client_message_id: &[u8],
        server_timestamp: u64,
        body: &[u8],
        identity_changed: bool,
    ) -> Result<Option<i64>, StorageError> {
        let server_timestamp = i64::try_from(server_timestamp).map_err(|_| StorageError::Sqlite)?;
        let client_message_id = (!client_message_id.is_empty()).then_some(client_message_id);
        self.db.with(|c| {
            let inserted = c.execute(
                "INSERT INTO received_messages
                     (sender_aci, sender_device_id, client_message_id, server_timestamp, body,
                      identity_changed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (sender_aci, sender_device_id, client_message_id) DO NOTHING",
                params![
                    from.aci(),
                    from.device_id(),
                    client_message_id,
                    server_timestamp,
                    body,
                    identity_changed
                ],
            )?;
            Ok((inserted > 0).then(|| c.last_insert_rowid()))
        })
    }

    /// Até `limit` mensagens com id maior que `after`, em ordem de id.
    pub(crate) fn after(&self, after: i64, limit: u32) -> Result<Vec<InboxMessage>, StorageError> {
        self.db.with(|c| {
            let mut select = c.prepare_cached(
                "SELECT id, sender_aci, sender_device_id, server_timestamp, body, identity_changed
                 FROM received_messages WHERE id > ?1 ORDER BY id LIMIT ?2",
            )?;
            let rows = select.query_map(params![after, limit], |row| {
                let aci: String = row.get(1)?;
                let from = Address::new(&aci, row.get(2)?).map_err(|_| corrupt(1, Type::Text))?;
                let server_timestamp =
                    u64::try_from(row.get::<_, i64>(3)?).map_err(|_| corrupt(3, Type::Integer))?;
                Ok(InboxMessage {
                    id: row.get(0)?,
                    from,
                    server_timestamp,
                    body: Plaintext::new(row.get(4)?),
                    identity_changed: row.get(5)?,
                })
            })?;
            rows.collect()
        })
    }

    /// Grava o recibo que `from` enviou com `client_message_id` e devolve o id dele, ou `None`
    /// se é um reenvio, como em [`Self::record`].
    pub(crate) fn record_receipt(
        &self,
        from: &Address,
        client_message_id: &[u8],
        server_timestamp: u64,
        kind: ReceiptType,
        message_ids: &[ClientMessageId],
    ) -> Result<Option<i64>, StorageError> {
        let server_timestamp = i64::try_from(server_timestamp).map_err(|_| StorageError::Sqlite)?;
        let client_message_id = (!client_message_id.is_empty()).then_some(client_message_id);
        self.db.with(|c| {
            let inserted = c.execute(
                "INSERT INTO received_receipts
                     (sender_aci, sender_device_id, client_message_id, kind, message_ids,
                      server_timestamp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT (sender_aci, sender_device_id, client_message_id) DO NOTHING",
                params![
                    from.aci(),
                    from.device_id(),
                    client_message_id,
                    receipt_code(kind),
                    join_ids(message_ids),
                    server_timestamp
                ],
            )?;
            Ok((inserted > 0).then(|| c.last_insert_rowid()))
        })
    }

    /// Até `limit` recibos com id maior que `after`, em ordem de id.
    pub(crate) fn receipts_after(
        &self,
        after: i64,
        limit: u32,
    ) -> Result<Vec<InboxReceipt>, StorageError> {
        self.db.with(|c| {
            let mut select = c.prepare_cached(
                "SELECT id, sender_aci, sender_device_id, kind, message_ids, server_timestamp
                 FROM received_receipts WHERE id > ?1 ORDER BY id LIMIT ?2",
            )?;
            let rows = select.query_map(params![after, limit], |row| {
                let aci: String = row.get(1)?;
                let from = Address::new(&aci, row.get(2)?).map_err(|_| corrupt(1, Type::Text))?;
                let kind =
                    receipt_from_code(row.get(3)?).ok_or_else(|| corrupt(3, Type::Integer))?;
                let ids: Vec<u8> = row.get(4)?;
                let client_message_ids = split_ids(&ids).ok_or_else(|| corrupt(4, Type::Blob))?;
                let server_timestamp =
                    u64::try_from(row.get::<_, i64>(5)?).map_err(|_| corrupt(5, Type::Integer))?;
                Ok(InboxReceipt {
                    id: row.get(0)?,
                    from,
                    kind,
                    client_message_ids,
                    server_timestamp,
                })
            })?;
            rows.collect()
        })
    }

    /// Para o recibo de leitura: o `client_message_id` das mensagens `ids` que têm um, agrupados
    /// pelo dispositivo que as enviou, na ordem em que foram gravadas. Ids inexistentes e
    /// mensagens sem `client_message_id` ficam de fora.
    pub(crate) fn senders_of(
        &self,
        ids: &[i64],
    ) -> Result<Vec<(Address, Vec<ClientMessageId>)>, StorageError> {
        self.db.with(|c| {
            let mut select = c.prepare_cached(
                "SELECT sender_aci, sender_device_id, client_message_id
                 FROM received_messages WHERE id = ?1 AND length(client_message_id) = ?2",
            )?;
            let id_len =
                i64::try_from(CLIENT_MESSAGE_ID_LEN).map_err(|_| corrupt(2, Type::Blob))?;
            let mut groups: Vec<(Address, Vec<ClientMessageId>)> = Vec::new();
            for id in ids {
                let found = select
                    .query_row(params![id, id_len], |row| {
                        let aci: String = row.get(0)?;
                        let from =
                            Address::new(&aci, row.get(1)?).map_err(|_| corrupt(0, Type::Text))?;
                        Ok((from, row.get::<_, ClientMessageId>(2)?))
                    })
                    .optional()?;
                let Some((from, client_message_id)) = found else {
                    continue;
                };
                match groups.iter_mut().find(|(sender, _)| *sender == from) {
                    Some((_, group)) => group.push(client_message_id),
                    None => groups.push((from, vec![client_message_id])),
                }
            }
            Ok(groups)
        })
    }
}

/// Código de `received_receipts.kind`. Publicado, um código nunca muda de sentido.
fn receipt_code(kind: ReceiptType) -> i64 {
    match kind {
        ReceiptType::Delivery => 1,
        ReceiptType::Read => 2,
    }
}

fn receipt_from_code(code: i64) -> Option<ReceiptType> {
    match code {
        1 => Some(ReceiptType::Delivery),
        2 => Some(ReceiptType::Read),
        _ => None,
    }
}

/// Opções do usuário que o núcleo aplica, no banco local para o app e a extensão de
/// notificação verem o mesmo. Clonar só copia o handle da conexão.
#[derive(Clone)]
pub(crate) struct Preferences {
    db: Arc<Database>,
}

impl Preferences {
    /// Opções sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Se este aparelho envia recibos de leitura e mostra os que recebe. Ligado por padrão.
    pub(crate) fn read_receipts(&self) -> Result<bool, StorageError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT read_receipts FROM settings WHERE id = 1",
                [],
                |row| row.get::<_, i64>(0).map(|value| value != 0),
            )
            .optional()
            .map(|value| value.unwrap_or(true))
        })
    }

    /// Liga ou desliga os recibos de leitura.
    pub(crate) fn set_read_receipts(&self, enabled: bool) -> Result<(), StorageError> {
        self.db.with(|c| {
            c.execute(
                "INSERT INTO settings (id, read_receipts) VALUES (1, ?1)
                 ON CONFLICT (id) DO UPDATE SET read_receipts = excluded.read_receipts",
                [i64::from(enabled)],
            )
        })?;
        Ok(())
    }
}

/// Valor fora da forma numa coluna: só o próprio núcleo grava as tabelas, então é banco
/// corrompido.
fn corrupt(column: usize, kind: Type) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, kind, Box::new(FromSqlError::InvalidType))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::DatabaseKey;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ACI: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    fn inbox() -> Result<Inbox, StorageError> {
        let key = DatabaseKey::from_bytes(&[1; 32])?;
        Ok(Inbox::new(Arc::new(Database::open_in_memory(&key)?)))
    }

    fn texts(messages: &[InboxMessage]) -> Vec<&[u8]> {
        messages.iter().map(|m| m.body.as_slice()).collect()
    }

    #[test]
    fn grava_e_le_em_ordem_a_partir_do_cursor() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 3)?;
        let first = inbox
            .record(&from, &[], 1_000, b"um", false)?
            .ok_or("não gravou")?;
        let second = inbox
            .record(&from, &[], 900, b"dois", true)?
            .ok_or("não gravou")?;
        assert!(second > first);

        let all = inbox.after(0, 10)?;
        assert_eq!(texts(&all), [&b"um"[..], b"dois"]);
        let message = all.first().ok_or("vazio")?;
        assert_eq!(message.id, first);
        assert_eq!(message.from, from);
        assert_eq!(message.server_timestamp, 1_000);
        assert!(!message.identity_changed);
        assert!(all.get(1).ok_or("sem a segunda")?.identity_changed);

        assert_eq!(texts(&inbox.after(first, 10)?), [&b"dois"[..]]);
        assert!(inbox.after(second, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn limite_pagina_a_leitura() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        for body in [b"a", b"b", b"c"] {
            inbox.record(&from, &[], 1, body, false)?;
        }
        let page = inbox.after(0, 2)?;
        assert_eq!(texts(&page), [&b"a"[..], b"b"]);
        let last = page.last().ok_or("vazio")?.id;
        assert_eq!(texts(&inbox.after(last, 2)?), [&b"c"[..]]);
        assert!(inbox.after(0, 0)?.is_empty());
        Ok(())
    }

    #[test]
    fn mensagem_gravada_na_transacao_desfeita_some() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        inbox.db.begin()?;
        let undone = inbox
            .record(&from, &[], 1, b"desfeita", false)?
            .ok_or("não gravou")?;
        inbox.db.rollback()?;
        assert!(inbox.after(0, 10)?.is_empty());
        // O id desfeito volta a ser usado: a mensagem reentregue fica com o mesmo cursor.
        assert_eq!(
            inbox.record(&from, &[], 1, b"reentregue", false)?,
            Some(undone)
        );
        Ok(())
    }

    #[test]
    fn id_nao_volta_depois_de_apagar_a_ultima() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        let deleted = inbox
            .record(&from, &[], 1, b"efemera", false)?
            .ok_or("não gravou")?;
        inbox
            .db
            .with(|c| c.execute("DELETE FROM received_messages", []))?;
        assert!(
            inbox
                .record(&from, &[], 1, b"nova", false)?
                .ok_or("não gravou")?
                > deleted
        );
        Ok(())
    }

    #[test]
    fn reenvio_com_o_mesmo_client_message_id_nao_e_gravado() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        let id = [7; 16];
        assert!(inbox.record(&from, &id, 1, b"oi", false)?.is_some());
        assert_eq!(inbox.record(&from, &id, 2, b"oi", false)?, None);
        assert_eq!(texts(&inbox.after(0, 10)?), [&b"oi"[..]]);
        Ok(())
    }

    #[test]
    fn mesmo_client_message_id_de_outro_remetente_ou_vazio_e_gravado() -> TestResult {
        let inbox = inbox()?;
        let id = [7; 16];
        let from = Address::new(ACI, 1)?;
        let other_device = Address::new(ACI, 2)?;
        let other_account = Address::new("0f0e0d0c-0000-4000-8000-000000000000", 1)?;
        for sender in [&from, &other_device, &other_account] {
            assert!(inbox.record(sender, &id, 1, b"oi", false)?.is_some());
        }
        assert!(inbox.record(&from, &[], 1, b"sem id", false)?.is_some());
        assert!(inbox.record(&from, &[], 1, b"sem id", false)?.is_some());
        assert_eq!(inbox.after(0, 10)?.len(), 5);
        Ok(())
    }

    #[test]
    fn instante_fora_da_faixa_do_sqlite_e_recusado() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        assert_eq!(
            inbox.record(&from, &[], u64::MAX, b"oi", false),
            Err(StorageError::Sqlite)
        );
        assert_eq!(
            inbox.record_receipt(&from, &[], u64::MAX, ReceiptType::Read, &[[1; 16]]),
            Err(StorageError::Sqlite)
        );
        Ok(())
    }

    #[test]
    fn recibos_sao_gravados_lidos_em_ordem_e_deduplicados() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 3)?;
        let envelope_id = [5; 16];
        let first = inbox
            .record_receipt(
                &from,
                &envelope_id,
                1_000,
                ReceiptType::Delivery,
                &[[1; 16]],
            )?
            .ok_or("não gravou")?;
        let second = inbox
            .record_receipt(&from, &[], 900, ReceiptType::Read, &[[1; 16], [2; 16]])?
            .ok_or("não gravou")?;
        assert!(second > first);
        // O reenvio do mesmo envelope não grava.
        assert_eq!(
            inbox.record_receipt(
                &from,
                &envelope_id,
                2_000,
                ReceiptType::Delivery,
                &[[1; 16]]
            )?,
            None
        );
        // Sem id, nada deduplica.
        assert!(
            inbox
                .record_receipt(&from, &[], 900, ReceiptType::Read, &[[1; 16], [2; 16]])?
                .is_some()
        );

        let all = inbox.receipts_after(0, 10)?;
        assert_eq!(all.len(), 3);
        assert_eq!(
            all[0],
            InboxReceipt {
                id: first,
                from: from.clone(),
                kind: ReceiptType::Delivery,
                client_message_ids: vec![[1; 16]],
                server_timestamp: 1_000,
            }
        );
        assert_eq!(all[1].id, second);
        assert_eq!(all[1].kind, ReceiptType::Read);
        assert_eq!(all[1].client_message_ids, [[1; 16], [2; 16]]);
        assert_eq!(inbox.receipts_after(first, 1)?, [all[1].clone()]);
        assert!(inbox.receipts_after(all[2].id, 10)?.is_empty());
        // Mensagens e recibos têm cursores separados.
        assert!(inbox.after(0, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn remetentes_das_mensagens_lidas_agrupados_na_ordem_de_gravacao() -> TestResult {
        let inbox = inbox()?;
        let alice = Address::new(ACI, 1)?;
        let carol = Address::new("0f0e0d0c-0000-4000-8000-000000000000", 2)?;
        let a1 = inbox
            .record(&alice, &[1; 16], 1, b"a1", false)?
            .ok_or("não gravou")?;
        let c1 = inbox
            .record(&carol, &[2; 16], 1, b"c1", false)?
            .ok_or("não gravou")?;
        let a2 = inbox
            .record(&alice, &[3; 16], 1, b"a2", false)?
            .ok_or("não gravou")?;
        let no_id = inbox
            .record(&alice, &[], 1, b"sem id", false)?
            .ok_or("não gravou")?;

        let groups = inbox.senders_of(&[a2, no_id, c1, a1, 9_999])?;
        assert_eq!(
            groups,
            [(alice, vec![[3; 16], [1; 16]]), (carol, vec![[2; 16]])]
        );
        assert!(inbox.senders_of(&[])?.is_empty());
        assert!(inbox.senders_of(&[no_id])?.is_empty());
        Ok(())
    }

    #[test]
    fn recibo_de_leitura_e_ligado_por_padrao_e_a_opcao_persiste() -> TestResult {
        let key = DatabaseKey::from_bytes(&[1; 32])?;
        let db = Arc::new(Database::open_in_memory(&key)?);
        let preferences = Preferences::new(db.clone());
        assert!(preferences.read_receipts()?);
        preferences.set_read_receipts(false)?;
        assert!(!Preferences::new(db.clone()).read_receipts()?);
        preferences.set_read_receipts(true)?;
        assert!(Preferences::new(db).read_receipts()?);
        Ok(())
    }
}
