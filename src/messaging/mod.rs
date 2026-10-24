//! Mensagens guardadas no banco local: as recebidas ([`Inbox`]) e as que esperam envio
//! ([`outbox`]).
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

pub(crate) mod outbox;

use std::sync::Arc;

use rusqlite::params;
use rusqlite::types::{FromSqlError, Type};

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

    /// Grava a mensagem que `from` enviou com `client_message_id` e devolve o id dela, ou `None`
    /// se `from` já tinha enviado uma mensagem com esse `client_message_id` (um reenvio), sem
    /// gravar nada. Um `client_message_id` vazio não deduplica. Dentro da transação de
    /// [`Database::begin`], só vale se ela for confirmada.
    pub(crate) fn record(
        &self,
        from: &Address,
        client_message_id: &[u8],
        server_timestamp: u64,
        body: &[u8],
    ) -> Result<Option<i64>, StorageError> {
        let server_timestamp = i64::try_from(server_timestamp).map_err(|_| StorageError::Sqlite)?;
        let client_message_id = (!client_message_id.is_empty()).then_some(client_message_id);
        self.db.with(|c| {
            let inserted = c.execute(
                "INSERT INTO received_messages
                     (sender_aci, sender_device_id, client_message_id, server_timestamp, body)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (sender_aci, sender_device_id, client_message_id) DO NOTHING",
                params![
                    from.aci(),
                    from.device_id(),
                    client_message_id,
                    server_timestamp,
                    body
                ],
            )?;
            Ok((inserted > 0).then(|| c.last_insert_rowid()))
        })
    }

    /// Até `limit` mensagens com id maior que `after`, em ordem de id.
    pub(crate) fn after(&self, after: i64, limit: u32) -> Result<Vec<InboxMessage>, StorageError> {
        self.db.with(|c| {
            let mut select = c.prepare_cached(
                "SELECT id, sender_aci, sender_device_id, server_timestamp, body
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
                })
            })?;
            rows.collect()
        })
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
            .record(&from, &[], 1_000, b"um")?
            .ok_or("não gravou")?;
        let second = inbox
            .record(&from, &[], 900, b"dois")?
            .ok_or("não gravou")?;
        assert!(second > first);

        let all = inbox.after(0, 10)?;
        assert_eq!(texts(&all), [&b"um"[..], b"dois"]);
        let message = all.first().ok_or("vazio")?;
        assert_eq!(message.id, first);
        assert_eq!(message.from, from);
        assert_eq!(message.server_timestamp, 1_000);

        assert_eq!(texts(&inbox.after(first, 10)?), [&b"dois"[..]]);
        assert!(inbox.after(second, 10)?.is_empty());
        Ok(())
    }

    #[test]
    fn limite_pagina_a_leitura() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        for body in [b"a", b"b", b"c"] {
            inbox.record(&from, &[], 1, body)?;
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
            .record(&from, &[], 1, b"desfeita")?
            .ok_or("não gravou")?;
        inbox.db.rollback()?;
        assert!(inbox.after(0, 10)?.is_empty());
        // O id desfeito volta a ser usado: a mensagem reentregue fica com o mesmo cursor.
        assert_eq!(inbox.record(&from, &[], 1, b"reentregue")?, Some(undone));
        Ok(())
    }

    #[test]
    fn id_nao_volta_depois_de_apagar_a_ultima() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        let deleted = inbox
            .record(&from, &[], 1, b"efemera")?
            .ok_or("não gravou")?;
        inbox
            .db
            .with(|c| c.execute("DELETE FROM received_messages", []))?;
        assert!(inbox.record(&from, &[], 1, b"nova")?.ok_or("não gravou")? > deleted);
        Ok(())
    }

    #[test]
    fn reenvio_com_o_mesmo_client_message_id_nao_e_gravado() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        let id = [7; 16];
        assert!(inbox.record(&from, &id, 1, b"oi")?.is_some());
        assert_eq!(inbox.record(&from, &id, 2, b"oi")?, None);
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
            assert!(inbox.record(sender, &id, 1, b"oi")?.is_some());
        }
        assert!(inbox.record(&from, &[], 1, b"sem id")?.is_some());
        assert!(inbox.record(&from, &[], 1, b"sem id")?.is_some());
        assert_eq!(inbox.after(0, 10)?.len(), 5);
        Ok(())
    }

    #[test]
    fn instante_fora_da_faixa_do_sqlite_e_recusado() -> TestResult {
        let inbox = inbox()?;
        let from = Address::new(ACI, 1)?;
        assert_eq!(
            inbox.record(&from, &[], u64::MAX, b"oi"),
            Err(StorageError::Sqlite)
        );
        Ok(())
    }
}
