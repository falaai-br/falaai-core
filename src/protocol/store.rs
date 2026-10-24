//! Stores da libsignal sobre o banco local cifrado ([`Database`]).
//!
//! Os registros são guardados no formato serializado da libsignal. Os que carregam segredo
//! (par de identidade, sessões, pré-chaves, sender keys) passam por buffers zerados ao sair de
//! escopo.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SenderKeyRecord,
    SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rusqlite::{OptionalExtension, Params, TransactionBehavior, params};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::access::PROFILE_KEY_LEN;
use super::signal::{SignalStores, StoreParts};
use super::{Address, ProtocolError};
use crate::storage::{Database, StorageError};

type SignalResult<T> = Result<T, SignalProtocolError>;

/// Implementa todos os stores da libsignal sobre uma conexão compartilhada. Clonar só copia o
/// handle da conexão (e a marca de identidade trocada, compartilhada entre os clones).
///
/// Identidades remotas seguem TOFU com safety numbers, como os apps do Signal: a primeira
/// chave vista é guardada e uma diferente a substitui ao chegar, deixando a troca marcada
/// ([`identity_changed`](Self::identity_changed)) para virar aviso na conversa. Receber nunca
/// é bloqueado. Enviar exige a chave guardada (uma sessão com a chave antiga não serve) e, em
/// conversa verificada, que ela seja a verificada: fora disso
/// [`IdentityKeyStore::is_trusted_identity`] recusa e a libsignal falha com
/// `UntrustedIdentity`, até o usuário verificar a nova ou aceitar a troca
/// ([`Self::set_identity_verified`]).
#[derive(Clone)]
pub(crate) struct SqliteStore {
    db: Arc<Database>,
    /// Ligada por [`IdentityKeyStore::save_identity`] ao trocar a chave guardada de um contato;
    /// [`SignalStores::begin`] desliga. Compartilhada pelos clones de [`SqliteStores`].
    identity_changed: Arc<AtomicBool>,
}

impl SqliteStore {
    /// Stores sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            identity_changed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// `true` se [`IdentityKeyStore::save_identity`] trocou a chave guardada de um contato por
    /// outra desde a última transação aberta por [`SignalStores::begin`].
    pub(crate) fn identity_changed(&self) -> bool {
        self.identity_changed.load(Ordering::Acquire)
    }

    /// Chave pública de identidade deste dispositivo. Exige as chaves da conta
    /// ([`ProtocolError::NoAccount`]).
    pub(crate) fn local_identity_key(&self) -> Result<IdentityKey, ProtocolError> {
        let key_pair = self
            .query_blob(
                "local_identity_key",
                "SELECT key_pair FROM local_identity",
                [],
            )
            .map_err(|_| ProtocolError::Storage)?
            .ok_or(ProtocolError::NoAccount)?;
        Ok(*IdentityKeyPair::try_from(&key_pair[..])?.identity_key())
    }

    /// Chave de identidade guardada para a conta de `peer`: a última vista num bundle ou numa
    /// mensagem dele. `None` enquanto não houve nenhum dos dois.
    pub(crate) fn peer_identity(
        &self,
        peer: &Address,
    ) -> Result<Option<IdentityKey>, ProtocolError> {
        self.query_blob(
            "peer_identity",
            "SELECT identity_key FROM identities WHERE name = ?1",
            [peer.aci()],
        )
        .map_err(|_| ProtocolError::Storage)?
        .map(|key| IdentityKey::decode(&key).map_err(ProtocolError::from))
        .transpose()
    }

    /// Chave que o usuário verificou para a conta de `peer`, se verificou alguma.
    fn verified_identity(&self, name: &str) -> Result<Option<IdentityKey>, ProtocolError> {
        self.query_blob(
            "verified_identity",
            "SELECT identity_key FROM verified_identities WHERE name = ?1",
            [name],
        )
        .map_err(|_| ProtocolError::Storage)?
        .map(|key| IdentityKey::decode(&key).map_err(ProtocolError::from))
        .transpose()
    }

    /// Situação da identidade da conta de `peer` frente ao que o usuário verificou.
    pub(crate) fn identity_status(
        &self,
        peer: &Address,
    ) -> Result<PeerIdentityStatus, ProtocolError> {
        Ok(
            match (
                self.peer_identity(peer)?,
                self.verified_identity(peer.aci())?,
            ) {
                (None, _) => PeerIdentityStatus::Unknown,
                (Some(_), None) => PeerIdentityStatus::Default,
                (Some(current), Some(verified)) if current == verified => {
                    PeerIdentityStatus::Verified
                }
                (Some(_), Some(_)) => PeerIdentityStatus::Changed,
            },
        )
    }

    /// Marca a chave atual da conta de `peer` como verificada pelo usuário (`true`), ou desfaz a
    /// verificação (`false`), o que também aceita uma troca de chave e libera o envio. Verificar
    /// exige uma chave guardada ([`ProtocolError::UnknownIdentity`]).
    pub(crate) fn set_identity_verified(
        &self,
        peer: &Address,
        verified: bool,
    ) -> Result<(), ProtocolError> {
        let name = peer.aci();
        if !verified {
            self.db
                .with(|c| c.execute("DELETE FROM verified_identities WHERE name = ?1", [name]))
                .map_err(|_| ProtocolError::Storage)?;
            return Ok(());
        }
        let pinned = self
            .db
            .with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                let pinned = tx.execute(
                    "INSERT INTO verified_identities (name, identity_key)
                     SELECT name, identity_key FROM identities WHERE name = ?1
                     ON CONFLICT (name) DO UPDATE SET identity_key = excluded.identity_key",
                    [name],
                )?;
                tx.commit()?;
                Ok(pinned)
            })
            .map_err(|_| ProtocolError::Storage)?;
        if pinned == 0 {
            return Err(ProtocolError::UnknownIdentity);
        }
        Ok(())
    }

    /// Grava identidade local e pré-chaves geradas no registro, numa transação. Falha com
    /// [`ProtocolError::AccountExists`] se já houver identidade: trocá-la invalida todas as
    /// sessões e não pode acontecer por engano.
    pub(crate) fn create_account(&self, account: &AccountRecords<'_>) -> Result<(), ProtocolError> {
        let identity = Zeroizing::new(account.identity.serialize());
        let signed_pre_key = (
            u32::from(account.signed_pre_key.id()?),
            Zeroizing::new(account.signed_pre_key.serialize()?),
        );
        let pre_keys = account
            .pre_keys
            .iter()
            .map(|r| Ok((u32::from(r.id()?), Zeroizing::new(r.serialize()?))))
            .collect::<SignalResult<Vec<_>>>()?;
        let kyber_pre_keys = account
            .kyber_pre_keys
            .iter()
            .map(|r| Ok((u32::from(r.id()?), Zeroizing::new(r.serialize()?), false)))
            .chain([Ok((
                u32::from(account.kyber_last_resort.id()?),
                Zeroizing::new(account.kyber_last_resort.serialize()?),
                true,
            ))])
            .collect::<SignalResult<Vec<_>>>()?;

        let created = self
            .db
            .with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if has_local_identity(&tx)? {
                    return Ok(false);
                }
                tx.execute(
                    "INSERT INTO local_identity (id, key_pair, registration_id) VALUES (1, ?1, ?2)",
                    params![&identity[..], account.registration_id],
                )?;
                tx.execute(
                    "INSERT INTO signed_pre_keys (id, record) VALUES (?1, ?2)",
                    params![signed_pre_key.0, &signed_pre_key.1[..]],
                )?;
                {
                    let mut insert =
                        tx.prepare("INSERT INTO pre_keys (id, record) VALUES (?1, ?2)")?;
                    for (id, record) in &pre_keys {
                        insert.execute(params![id, &record[..]])?;
                    }
                    let mut insert = tx.prepare(
                        "INSERT INTO kyber_pre_keys (id, record, last_resort) VALUES (?1, ?2, ?3)",
                    )?;
                    for (id, record, last_resort) in &kyber_pre_keys {
                        insert.execute(params![id, &record[..], last_resort])?;
                    }
                }
                tx.commit()?;
                Ok(true)
            })
            .map_err(|_| ProtocolError::Storage)?;
        if created {
            Ok(())
        } else {
            Err(ProtocolError::AccountExists)
        }
    }

    /// Endereço deste dispositivo, se o registro já o gravou.
    pub(crate) fn local_address(&self) -> Result<Option<Address>, ProtocolError> {
        self.db
            .with(|c| {
                c.query_row("SELECT aci, device_id FROM local_address", [], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, u8>(1)?))
                })
                .optional()
            })
            .map_err(|_| ProtocolError::Storage)?
            .map(|(aci, device_id)| Address::new(&aci, device_id))
            .transpose()
    }

    /// Grava o endereço que o servidor atribuiu a este dispositivo no registro. Exige as chaves
    /// da conta ([`ProtocolError::NoAccount`]). Gravar de novo o mesmo endereço não muda nada;
    /// um diferente falha com [`ProtocolError::AccountExists`].
    pub(crate) fn set_local_address(&self, address: &Address) -> Result<(), ProtocolError> {
        enum Outcome {
            Saved,
            NoAccount,
            Conflict,
        }
        let (aci, device_id) = (address.0.name(), u8::from(address.0.device_id()));
        let outcome = self
            .db
            .with(|c| {
                let tx = c.transaction_with_behavior(TransactionBehavior::Immediate)?;
                if !has_local_identity(&tx)? {
                    return Ok(Outcome::NoAccount);
                }
                let current: Option<(String, u8)> = tx
                    .query_row("SELECT aci, device_id FROM local_address", [], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })
                    .optional()?;
                let outcome = match current {
                    None => {
                        tx.execute(
                            "INSERT INTO local_address (id, aci, device_id) VALUES (1, ?1, ?2)",
                            params![aci, device_id],
                        )?;
                        Outcome::Saved
                    }
                    Some(current) if current == (aci.to_owned(), device_id) => Outcome::Saved,
                    Some(_) => Outcome::Conflict,
                };
                tx.commit()?;
                Ok(outcome)
            })
            .map_err(|_| ProtocolError::Storage)?;
        match outcome {
            Outcome::Saved => Ok(()),
            Outcome::NoAccount => Err(ProtocolError::NoAccount),
            Outcome::Conflict => Err(ProtocolError::AccountExists),
        }
    }

    /// Profile key da conta de `peer`, se já chegou pelo canal E2EE.
    pub(crate) fn peer_profile_key(
        &self,
        peer: &Address,
    ) -> Result<Option<Zeroizing<[u8; PROFILE_KEY_LEN]>>, ProtocolError> {
        let stored = self
            .db
            .with(|c| {
                c.query_row(
                    "SELECT profile_key FROM peer_profile_keys WHERE aci = ?1",
                    [peer.aci()],
                    |row| row.get::<_, Vec<u8>>(0).map(Zeroizing::new),
                )
                .optional()
            })
            .map_err(|_| ProtocolError::Storage)?;
        stored
            .map(|bytes| {
                let mut key = Zeroizing::new([0; PROFILE_KEY_LEN]);
                if bytes.len() != key.len() {
                    return Err(ProtocolError::Storage);
                }
                key.copy_from_slice(&bytes);
                Ok(key)
            })
            .transpose()
    }

    /// Grava (ou troca) a profile key da conta de `peer`.
    ///
    /// Só os testes gravam por enquanto: a profile key chega dentro do conteúdo E2EE, que ainda
    /// não tem esse campo.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_peer_profile_key(
        &self,
        peer: &Address,
        profile_key: &[u8; PROFILE_KEY_LEN],
    ) -> Result<(), ProtocolError> {
        self.db
            .with(|c| {
                c.execute(
                    "INSERT INTO peer_profile_keys (aci, profile_key) VALUES (?1, ?2) \
                     ON CONFLICT (aci) DO UPDATE SET profile_key = excluded.profile_key",
                    params![peer.aci(), profile_key.as_slice()],
                )
            })
            .map_err(|_| ProtocolError::Storage)?;
        Ok(())
    }

    /// Grava só a identidade local, sem pré-chaves.
    #[cfg(test)]
    pub(crate) fn create_local_identity(
        &self,
        key_pair: &IdentityKeyPair,
        registration_id: u32,
    ) -> Result<(), ProtocolError> {
        let key_pair = Zeroizing::new(key_pair.serialize());
        self.db
            .with(|c| {
                c.execute(
                    "INSERT INTO local_identity (id, key_pair, registration_id) VALUES (1, ?1, ?2)",
                    params![&key_pair[..], registration_id],
                )
            })
            .map_err(|_| ProtocolError::Storage)?;
        Ok(())
    }

    /// Guarda uma pré-chave Kyber de último recurso: sobrevive ao uso, mas cada combinação de
    /// pré-chaves e base key só é aceita uma vez.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "rotação da Kyber de último recurso; no registro ela entra por create_account"
        )
    )]
    pub(crate) fn save_last_resort_kyber_pre_key(
        &self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        let record = Zeroizing::new(record.serialize().map_err(ProtocolError::from)?);
        self.db
            .with(|c| {
                c.execute(
                    "INSERT INTO kyber_pre_keys (id, record, last_resort) VALUES (?1, ?2, 1)
                     ON CONFLICT (id) DO UPDATE SET record = excluded.record, last_resort = 1",
                    params![u32::from(id), &record[..]],
                )
            })
            .map_err(|_| ProtocolError::Storage)?;
        Ok(())
    }

    fn query_blob<P: Params>(
        &self,
        method: &'static str,
        sql: &str,
        params: P,
    ) -> SignalResult<Option<Zeroizing<Vec<u8>>>> {
        self.db
            .with(|c| {
                c.prepare_cached(sql)?
                    .query_row(params, |row| row.get(0).map(Zeroizing::new))
                    .optional()
            })
            .map_err(SignalProtocolError::for_application_callback(method))
    }

    fn execute<P: Params>(&self, method: &'static str, sql: &str, params: P) -> SignalResult<()> {
        self.db
            .with(|c| c.prepare_cached(sql)?.execute(params))
            .map_err(SignalProtocolError::for_application_callback(method))?;
        Ok(())
    }
}

/// Registros gerados no registro da conta, gravados juntos por [`SqliteStore::create_account`].
pub(crate) struct AccountRecords<'a> {
    pub(crate) identity: &'a IdentityKeyPair,
    pub(crate) registration_id: u32,
    pub(crate) signed_pre_key: &'a SignedPreKeyRecord,
    pub(crate) pre_keys: &'a [PreKeyRecord],
    pub(crate) kyber_pre_keys: &'a [KyberPreKeyRecord],
    pub(crate) kyber_last_resort: &'a KyberPreKeyRecord,
}

/// Situação da identidade de um contato frente ao que o usuário verificou.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerIdentityStatus {
    /// Nenhuma chave guardada: ainda não houve bundle nem mensagem dele.
    Unknown,
    /// Chave guardada na primeira vista (TOFU), sem verificação do usuário.
    Default,
    /// A chave guardada é a que o usuário verificou.
    Verified,
    /// O usuário verificou uma chave e a guardada agora é outra: o envio está bloqueado até ele
    /// verificar a nova ou aceitar a troca.
    Changed,
}

fn has_local_identity(c: &rusqlite::Connection) -> rusqlite::Result<bool> {
    c.query_row("SELECT EXISTS (SELECT 1 FROM local_identity)", [], |row| {
        row.get(0)
    })
}

fn device_id(address: &ProtocolAddress) -> u32 {
    u32::from(address.device_id())
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteStore {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        const METHOD: &str = "get_identity_key_pair";
        let key_pair = self
            .query_blob(METHOD, "SELECT key_pair FROM local_identity", [])?
            .ok_or_else(|| SignalProtocolError::InvalidState(METHOD, "sem identidade".into()))?;
        IdentityKeyPair::try_from(&key_pair[..])
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        const METHOD: &str = "get_local_registration_id";
        self.db
            .with(|c| {
                c.query_row("SELECT registration_id FROM local_identity", [], |row| {
                    row.get(0)
                })
                .optional()
            })
            .map_err(SignalProtocolError::for_application_callback(METHOD))?
            .ok_or_else(|| SignalProtocolError::InvalidState(METHOD, "sem identidade".into()))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let previous = self.get_identity(address).await?;
        if previous.as_ref() == Some(identity) {
            return Ok(IdentityChange::NewOrUnchanged);
        }
        self.execute(
            "save_identity",
            "INSERT INTO identities (name, identity_key) VALUES (?1, ?2)
             ON CONFLICT (name) DO UPDATE SET identity_key = excluded.identity_key",
            params![address.name(), &identity.serialize()[..]],
        )?;
        if previous.is_some() {
            self.identity_changed.store(true, Ordering::Release);
        }
        Ok(IdentityChange::from_changed(previous.is_some()))
    }

    /// Receber é sempre confiável: a chave nova substitui a guardada e a troca vira aviso.
    /// Enviar é confiável se a chave é a guardada (ou ainda não há nenhuma) e, havendo uma
    /// verificada, se é ela. Como no Signal, a sessão com a chave antiga não envia depois que
    /// uma nova foi guardada.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> SignalResult<bool> {
        match direction {
            Direction::Receiving => Ok(true),
            Direction::Sending => {
                let stored = self.get_identity(address).await?;
                let verified = self.verified_identity(address.name()).map_err(
                    SignalProtocolError::for_application_callback("is_trusted_identity"),
                )?;
                Ok(stored.is_none_or(|stored| stored == *identity)
                    && verified.is_none_or(|verified| verified == *identity))
            }
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        self.query_blob(
            "get_identity",
            "SELECT identity_key FROM identities WHERE name = ?1",
            [address.name()],
        )?
        .map(|key| IdentityKey::decode(&key))
        .transpose()
    }
}

#[async_trait(?Send)]
impl SessionStore for SqliteStore {
    async fn load_session(&self, address: &ProtocolAddress) -> SignalResult<Option<SessionRecord>> {
        self.query_blob(
            "load_session",
            "SELECT record FROM sessions WHERE name = ?1 AND device_id = ?2",
            params![address.name(), device_id(address)],
        )?
        .map(|record| SessionRecord::deserialize(&record))
        .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> SignalResult<()> {
        let record = Zeroizing::new(record.serialize()?);
        self.execute(
            "store_session",
            "INSERT INTO sessions (name, device_id, record) VALUES (?1, ?2, ?3)
             ON CONFLICT (name, device_id) DO UPDATE SET record = excluded.record",
            params![address.name(), device_id(address), &record[..]],
        )
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteStore {
    async fn get_pre_key(&self, id: PreKeyId) -> SignalResult<PreKeyRecord> {
        let record = self
            .query_blob(
                "get_pre_key",
                "SELECT record FROM pre_keys WHERE id = ?1",
                [u32::from(id)],
            )?
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&record)
    }

    async fn save_pre_key(&mut self, id: PreKeyId, record: &PreKeyRecord) -> SignalResult<()> {
        let record = Zeroizing::new(record.serialize()?);
        self.execute(
            "save_pre_key",
            "INSERT OR REPLACE INTO pre_keys (id, record) VALUES (?1, ?2)",
            params![u32::from(id), &record[..]],
        )
    }

    async fn remove_pre_key(&mut self, id: PreKeyId) -> SignalResult<()> {
        self.execute(
            "remove_pre_key",
            "DELETE FROM pre_keys WHERE id = ?1",
            [u32::from(id)],
        )
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteStore {
    async fn get_signed_pre_key(&self, id: SignedPreKeyId) -> SignalResult<SignedPreKeyRecord> {
        let record = self
            .query_blob(
                "get_signed_pre_key",
                "SELECT record FROM signed_pre_keys WHERE id = ?1",
                [u32::from(id)],
            )?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&record)
    }

    async fn save_signed_pre_key(
        &mut self,
        id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> SignalResult<()> {
        let record = Zeroizing::new(record.serialize()?);
        self.execute(
            "save_signed_pre_key",
            "INSERT OR REPLACE INTO signed_pre_keys (id, record) VALUES (?1, ?2)",
            params![u32::from(id), &record[..]],
        )
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteStore {
    async fn get_kyber_pre_key(&self, id: KyberPreKeyId) -> SignalResult<KyberPreKeyRecord> {
        let record = self
            .query_blob(
                "get_kyber_pre_key",
                "SELECT record FROM kyber_pre_keys WHERE id = ?1",
                [u32::from(id)],
            )?
            .ok_or(SignalProtocolError::InvalidKyberPreKeyId)?;
        KyberPreKeyRecord::deserialize(&record)
    }

    /// Guarda uma pré-chave Kyber descartável. Regravar uma de último recurso mantém o tipo.
    async fn save_kyber_pre_key(
        &mut self,
        id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> SignalResult<()> {
        let record = Zeroizing::new(record.serialize()?);
        self.execute(
            "save_kyber_pre_key",
            "INSERT INTO kyber_pre_keys (id, record, last_resort) VALUES (?1, ?2, 0)
             ON CONFLICT (id) DO UPDATE SET record = excluded.record",
            params![u32::from(id), &record[..]],
        )
    }

    /// Apaga a descartável; na de último recurso, registra a base key e recusa repetição.
    async fn mark_kyber_pre_key_used(
        &mut self,
        id: KyberPreKeyId,
        signed_pre_key_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> SignalResult<()> {
        enum Outcome {
            Missing,
            Used,
            Replayed,
        }
        let (id, signed_pre_key_id) = (u32::from(id), u32::from(signed_pre_key_id));
        let base_key = base_key.serialize();
        let outcome = self
            .db
            .with(|c| {
                // Savepoint e não transação: roda dentro da transação do decrypt.
                let tx = c.savepoint()?;
                let last_resort: Option<bool> = tx
                    .query_row(
                        "SELECT last_resort FROM kyber_pre_keys WHERE id = ?1",
                        [id],
                        |row| row.get(0),
                    )
                    .optional()?;
                let outcome = match last_resort {
                    None => Outcome::Missing,
                    Some(false) => {
                        tx.execute("DELETE FROM kyber_pre_keys WHERE id = ?1", [id])?;
                        Outcome::Used
                    }
                    Some(true) => {
                        let inserted = tx.execute(
                            "INSERT OR IGNORE INTO kyber_base_keys_seen
                             (kyber_pre_key_id, signed_pre_key_id, base_key) VALUES (?1, ?2, ?3)",
                            params![id, signed_pre_key_id, &base_key[..]],
                        )?;
                        if inserted == 0 {
                            Outcome::Replayed
                        } else {
                            Outcome::Used
                        }
                    }
                };
                tx.commit()?;
                Ok(outcome)
            })
            .map_err(
                SignalProtocolError::for_application_callback::<StorageError>(
                    "mark_kyber_pre_key_used",
                ),
            )?;
        match outcome {
            Outcome::Used => Ok(()),
            Outcome::Missing => Err(SignalProtocolError::InvalidKyberPreKeyId),
            Outcome::Replayed => Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                "reused base key".to_owned(),
            )),
        }
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SqliteStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> SignalResult<()> {
        let record = Zeroizing::new(record.serialize()?);
        self.execute(
            "store_sender_key",
            "INSERT INTO sender_keys (name, device_id, distribution_id, record)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (name, device_id, distribution_id) DO UPDATE SET record = excluded.record",
            params![
                sender.name(),
                device_id(sender),
                &distribution_id.as_bytes()[..],
                &record[..]
            ],
        )
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> SignalResult<Option<SenderKeyRecord>> {
        self.query_blob(
            "load_sender_key",
            "SELECT record FROM sender_keys
             WHERE name = ?1 AND device_id = ?2 AND distribution_id = ?3",
            params![
                sender.name(),
                device_id(sender),
                &distribution_id.as_bytes()[..]
            ],
        )?
        .map(|record| SenderKeyRecord::deserialize(&record))
        .transpose()
    }
}

/// [`SignalStores`] sobre o banco local. [`StoreParts`] empresta cada store separadamente;
/// aqui todos são handles da mesma conexão.
pub(crate) struct SqliteStores {
    db: Arc<Database>,
    sessions: SqliteStore,
    identities: SqliteStore,
    pre_keys: SqliteStore,
    signed_pre_keys: SqliteStore,
    kyber_pre_keys: SqliteStore,
}

impl SqliteStores {
    /// Stores sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        let store = SqliteStore::new(db.clone());
        Self {
            db,
            sessions: store.clone(),
            identities: store.clone(),
            pre_keys: store.clone(),
            signed_pre_keys: store.clone(),
            kyber_pre_keys: store,
        }
    }
}

impl SignalStores for SqliteStores {
    fn parts(&mut self) -> StoreParts<'_> {
        StoreParts {
            sessions: &mut self.sessions,
            identities: &mut self.identities,
            pre_keys: &mut self.pre_keys,
            signed_pre_keys: &mut self.signed_pre_keys,
            kyber_pre_keys: &mut self.kyber_pre_keys,
        }
    }

    fn begin(&mut self) -> Result<(), ProtocolError> {
        self.db.begin().map_err(transaction_error)?;
        self.identities
            .identity_changed
            .store(false, Ordering::Release);
        Ok(())
    }

    fn commit(&mut self) -> Result<(), ProtocolError> {
        self.db.commit().map_err(transaction_error)
    }

    fn rollback(&mut self) {
        // Só falha se a conexão já desfez a transação sozinha.
        let _ = self.db.rollback();
    }

    fn identity_changed(&self) -> bool {
        self.identities.identity_changed()
    }
}

fn transaction_error(error: StorageError) -> ProtocolError {
    match error {
        StorageError::Busy => ProtocolError::Busy,
        _ => ProtocolError::Storage,
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::path::{Path, PathBuf};

    use libsignal_protocol::{
        Aci, DeviceId, KeyPair, create_sender_key_distribution_message, group_decrypt,
        group_encrypt, kem, process_sender_key_distribution_message,
    };

    use super::*;
    use crate::protocol::certificate::{self, CertificateIssuer, TrustRoot};
    use crate::protocol::signal::LibsignalSessions;
    use crate::protocol::testing::{self, ready};
    use crate::protocol::{Address, Ciphertext, CiphertextKind, Decrypted, Sessions};
    use crate::storage::DatabaseKey;

    type TestResult = Result<(), Box<dyn Error>>;

    fn key() -> Result<DatabaseKey, StorageError> {
        DatabaseKey::from_bytes(&[0x5A; 32])
    }

    fn store() -> Result<SqliteStore, Box<dyn Error>> {
        Ok(SqliteStore::new(Arc::new(Database::open_in_memory(
            &key()?
        )?)))
    }

    fn address(seed: u8, device_id: u8) -> Result<ProtocolAddress, Box<dyn Error>> {
        Ok(ProtocolAddress::new(
            Aci::from_uuid_bytes([seed; 16]).service_id_string(),
            DeviceId::new(device_id)?,
        ))
    }

    #[test]
    fn identidade_local_e_gravada_uma_vez() -> TestResult {
        let store = store()?;
        assert!(matches!(
            ready(store.get_identity_key_pair())?,
            Err(SignalProtocolError::InvalidState(..))
        ));
        assert!(ready(store.get_local_registration_id())?.is_err());

        let identity = IdentityKeyPair::generate(&mut rand::rng());
        store.create_local_identity(&identity, 42)?;
        let loaded = ready(store.get_identity_key_pair())??;
        assert_eq!(loaded.serialize(), identity.serialize());
        assert_eq!(ready(store.get_local_registration_id())??, 42);

        let other = IdentityKeyPair::generate(&mut rand::rng());
        assert_eq!(
            store.create_local_identity(&other, 7),
            Err(ProtocolError::Storage)
        );
        let kept = ready(store.get_identity_key_pair())??;
        assert_eq!(kept.serialize(), identity.serialize());
        assert_eq!(ready(store.get_local_registration_id())??, 42);
        Ok(())
    }

    #[test]
    fn profile_key_do_contato_e_por_conta_e_pode_trocar() -> TestResult {
        let store = store()?;
        let bob = Address::new("b0b0b0b0-0000-4000-8000-000000000000", 1)?;
        let bob_other_device = Address::new("b0b0b0b0-0000-4000-8000-000000000000", 2)?;
        let carol = Address::new("c0c0c0c0-0000-4000-8000-000000000000", 1)?;
        assert!(store.peer_profile_key(&bob)?.is_none());

        store.set_peer_profile_key(&bob, &[0x01; PROFILE_KEY_LEN])?;
        assert_eq!(
            store.peer_profile_key(&bob_other_device)?.as_deref(),
            Some(&[0x01; PROFILE_KEY_LEN])
        );
        assert!(store.peer_profile_key(&carol)?.is_none());

        store.set_peer_profile_key(&bob, &[0x02; PROFILE_KEY_LEN])?;
        assert_eq!(
            store.peer_profile_key(&bob)?.as_deref(),
            Some(&[0x02; PROFILE_KEY_LEN])
        );
        Ok(())
    }

    fn identity_key() -> IdentityKey {
        *IdentityKeyPair::generate(&mut rand::rng()).identity_key()
    }

    /// Confiança nos dois sentidos para `identity` como chave de `address`.
    fn trusted(
        store: &SqliteStore,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<(bool, bool), Box<dyn Error>> {
        Ok((
            ready(store.is_trusted_identity(address, identity, Direction::Sending))??,
            ready(store.is_trusted_identity(address, identity, Direction::Receiving))??,
        ))
    }

    #[test]
    fn identidade_remota_nao_verificada_segue_tofu_e_aceita_a_troca() -> TestResult {
        let mut store = store()?;
        let bob = address(0xB0, 1)?;
        let (first, second) = (identity_key(), identity_key());
        let bob_account = Address::new(bob.name(), 1)?;

        assert_eq!(ready(store.get_identity(&bob))??, None);
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Unknown
        );
        assert_eq!(trusted(&store, &bob, &first)?, (true, true));

        assert_eq!(
            ready(store.save_identity(&bob, &first))??,
            IdentityChange::NewOrUnchanged
        );
        assert!(!store.identity_changed());
        assert_eq!(
            ready(store.save_identity(&bob, &first))??,
            IdentityChange::NewOrUnchanged
        );
        assert!(!store.identity_changed());
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Default
        );
        assert_eq!(trusted(&store, &bob, &first)?, (true, true));
        // Sem verificação, a chave nova é aceita ao chegar e a troca fica marcada; enviar só
        // com a chave guardada.
        assert_eq!(trusted(&store, &bob, &second)?, (false, true));
        assert_eq!(
            ready(store.save_identity(&bob, &second))??,
            IdentityChange::ReplacedExisting
        );
        assert!(store.identity_changed());
        assert_eq!(ready(store.get_identity(&bob))??, Some(second));
        assert_eq!(store.peer_identity(&bob_account)?, Some(second));
        assert_eq!(trusted(&store, &bob, &second)?, (true, true));
        assert_eq!(trusted(&store, &bob, &first)?, (false, true));
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Default
        );
        Ok(())
    }

    #[test]
    fn identidade_verificada_bloqueia_envio_quando_muda_e_nunca_bloqueia_receber() -> TestResult {
        let mut store = store()?;
        let bob = address(0xB0, 1)?;
        let bob_account = Address::new(bob.name(), 1)?;
        let (first, second) = (identity_key(), identity_key());

        assert_eq!(
            store.set_identity_verified(&bob_account, true),
            Err(ProtocolError::UnknownIdentity)
        );
        ready(store.save_identity(&bob, &first))??;
        store.set_identity_verified(&bob_account, true)?;
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Verified
        );
        assert_eq!(trusted(&store, &bob, &first)?, (true, true));
        assert_eq!(trusted(&store, &bob, &second)?, (false, true));

        // A chave nova chega numa mensagem: é guardada, a verificada fica pinada na antiga.
        assert_eq!(
            ready(store.save_identity(&bob, &second))??,
            IdentityChange::ReplacedExisting
        );
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Changed
        );
        // Nem a nova (não é a verificada) nem a antiga (não é a guardada) enviam.
        assert_eq!(trusted(&store, &bob, &second)?, (false, true));
        assert_eq!(trusted(&store, &bob, &first)?, (false, true));

        // Verificar de novo pina a chave atual e libera; desfazer a verificação também.
        store.set_identity_verified(&bob_account, true)?;
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Verified
        );
        assert_eq!(trusted(&store, &bob, &second)?, (true, true));
        assert_eq!(trusted(&store, &bob, &first)?, (false, true));
        store.set_identity_verified(&bob_account, false)?;
        assert_eq!(
            store.identity_status(&bob_account)?,
            PeerIdentityStatus::Default
        );
        assert_eq!(trusted(&store, &bob, &second)?, (true, true));
        assert_eq!(trusted(&store, &bob, &first)?, (false, true));
        store.set_identity_verified(&bob_account, false)?;
        Ok(())
    }

    #[test]
    fn verificacao_e_por_conta_e_nao_vaza_para_outro_contato() -> TestResult {
        let mut store = store()?;
        let bob = address(0xB0, 1)?;
        let carol = address(0xC0, 1)?;
        let key = identity_key();
        ready(store.save_identity(&bob, &key))??;
        ready(store.save_identity(&carol, &key))??;
        store.set_identity_verified(&Address::new(bob.name(), 1)?, true)?;
        assert_eq!(
            store.identity_status(&Address::new(bob.name(), 2)?)?,
            PeerIdentityStatus::Verified
        );
        assert_eq!(
            store.identity_status(&Address::new(carol.name(), 1)?)?,
            PeerIdentityStatus::Default
        );
        Ok(())
    }

    #[test]
    fn chave_de_identidade_local_exige_conta() -> TestResult {
        let store = store()?;
        assert_eq!(store.local_identity_key(), Err(ProtocolError::NoAccount));
        let identity = IdentityKeyPair::generate(&mut rand::rng());
        store.create_local_identity(&identity, 42)?;
        assert_eq!(store.local_identity_key()?, *identity.identity_key());
        Ok(())
    }

    #[test]
    fn identidade_remota_e_da_conta_nao_do_dispositivo() -> TestResult {
        let mut store = store()?;
        let identity = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();
        ready(store.save_identity(&address(0xB0, 1)?, &identity))??;
        assert_eq!(
            ready(store.get_identity(&address(0xB0, 2)?))??,
            Some(identity)
        );
        assert_eq!(ready(store.get_identity(&address(0xC0, 1)?))??, None);
        Ok(())
    }

    #[test]
    fn sessao_e_gravada_por_dispositivo() -> TestResult {
        let mut store = store()?;
        let device_1 = address(0xB0, 1)?;
        assert!(ready(store.load_session(&device_1))??.is_none());
        ready(store.store_session(&device_1, &SessionRecord::new_fresh()))??;
        let loaded = ready(store.load_session(&device_1))??;
        assert!(loaded.is_some());
        assert!(ready(store.load_session(&address(0xB0, 2)?))??.is_none());
        Ok(())
    }

    #[test]
    fn pre_chave_descartavel_e_gravada_e_removida() -> TestResult {
        let mut store = store()?;
        let record = PreKeyRecord::new(5.into(), &KeyPair::generate(&mut rand::rng()));
        assert!(matches!(
            ready(store.get_pre_key(5.into()))?,
            Err(SignalProtocolError::InvalidPreKeyId)
        ));
        ready(store.save_pre_key(5.into(), &record))??;
        assert_eq!(
            ready(store.get_pre_key(5.into()))??.serialize()?,
            record.serialize()?
        );
        ready(store.remove_pre_key(5.into()))??;
        assert!(matches!(
            ready(store.get_pre_key(5.into()))?,
            Err(SignalProtocolError::InvalidPreKeyId)
        ));
        ready(store.remove_pre_key(5.into()))??;
        Ok(())
    }

    #[test]
    fn pre_chave_assinada_e_gravada() -> TestResult {
        let mut store = store()?;
        let identity = IdentityKeyPair::generate(&mut rand::rng());
        let key_pair = KeyPair::generate(&mut rand::rng());
        let signature = identity
            .private_key()
            .calculate_signature(&key_pair.public_key.serialize(), &mut rand::rng())?;
        let record = SignedPreKeyRecord::new(
            3.into(),
            libsignal_protocol::Timestamp::from_epoch_millis(0),
            &key_pair,
            &signature,
        );
        assert!(matches!(
            ready(store.get_signed_pre_key(3.into()))?,
            Err(SignalProtocolError::InvalidSignedPreKeyId)
        ));
        ready(store.save_signed_pre_key(3.into(), &record))??;
        assert_eq!(
            ready(store.get_signed_pre_key(3.into()))??.serialize()?,
            record.serialize()?
        );
        Ok(())
    }

    fn kyber_record(id: u32) -> Result<KyberPreKeyRecord, Box<dyn Error>> {
        let identity = IdentityKeyPair::generate(&mut rand::rng());
        Ok(KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id.into(),
            identity.private_key(),
        )?)
    }

    #[test]
    fn kyber_descartavel_some_no_uso() -> TestResult {
        let mut store = store()?;
        let base_key = KeyPair::generate(&mut rand::rng()).public_key;
        ready(store.save_kyber_pre_key(9.into(), &kyber_record(9)?))??;
        ready(store.get_kyber_pre_key(9.into()))??;
        ready(store.mark_kyber_pre_key_used(9.into(), 1.into(), &base_key))??;
        assert!(matches!(
            ready(store.get_kyber_pre_key(9.into()))?,
            Err(SignalProtocolError::InvalidKyberPreKeyId)
        ));
        assert!(matches!(
            ready(store.mark_kyber_pre_key_used(9.into(), 1.into(), &base_key))?,
            Err(SignalProtocolError::InvalidKyberPreKeyId)
        ));
        Ok(())
    }

    #[test]
    fn kyber_de_ultimo_recurso_fica_e_recusa_base_key_repetida() -> TestResult {
        let mut store = store()?;
        let rng = &mut rand::rng();
        let (first, second) = (
            KeyPair::generate(rng).public_key,
            KeyPair::generate(rng).public_key,
        );
        store.save_last_resort_kyber_pre_key(9.into(), &kyber_record(9)?)?;
        // Regravar pelo trait não rebaixa para descartável.
        ready(store.save_kyber_pre_key(9.into(), &kyber_record(9)?))??;

        ready(store.mark_kyber_pre_key_used(9.into(), 1.into(), &first))??;
        ready(store.get_kyber_pre_key(9.into()))??;
        assert!(matches!(
            ready(store.mark_kyber_pre_key_used(9.into(), 1.into(), &first))?,
            Err(SignalProtocolError::InvalidMessage(
                CiphertextMessageType::PreKey,
                _
            ))
        ));
        ready(store.mark_kyber_pre_key_used(9.into(), 2.into(), &first))??;
        ready(store.mark_kyber_pre_key_used(9.into(), 1.into(), &second))??;
        Ok(())
    }

    #[test]
    fn sender_key_cifra_e_decifra_mensagem_de_grupo() -> TestResult {
        let (mut alice, mut bob) = (store()?, store()?);
        let sender = address(0xA1, 1)?;
        let distribution_id = Uuid::from_bytes([7; 16]);
        let rng = &mut rand::rng();

        let distribution = ready(create_sender_key_distribution_message(
            &sender,
            distribution_id,
            &mut alice,
            rng,
        ))??;
        ready(process_sender_key_distribution_message(
            &sender,
            &distribution,
            &mut bob,
        ))??;
        let message = ready(group_encrypt(
            &mut alice,
            &sender,
            distribution_id,
            b"oi, grupo",
            rng,
        ))??;
        let plaintext = ready(group_decrypt(message.serialized(), &mut bob, &sender))??;
        assert_eq!(plaintext, b"oi, grupo");

        let other = Uuid::from_bytes([8; 16]);
        assert!(ready(bob.load_sender_key(&sender, other))??.is_none());
        Ok(())
    }

    /// Dispositivo com banco SQLCipher em arquivo, que pode ser fechado e reaberto.
    struct Device {
        address: Address,
        path: PathBuf,
        db: Arc<Database>,
        trust_root: Vec<u8>,
        /// Certificado de remetente, entregue de novo a cada reabertura.
        certificate: Vec<u8>,
        sessions: LibsignalSessions<SqliteStores>,
    }

    impl Device {
        fn new(dir: &Path, seed: u8, server: &CertificateIssuer) -> Result<Self, Box<dyn Error>> {
            let path = dir.join(format!("{seed:02x}.db"));
            let db = Arc::new(Database::open(&path, &key()?)?);
            let identity = IdentityKeyPair::generate(&mut rand::rng());
            SqliteStore::new(db.clone()).create_local_identity(&identity, u32::from(seed))?;
            let address = Address::new(&Aci::from_uuid_bytes([seed; 16]).service_id_string(), 1)?;
            let expiration = certificate::now()?.add_millis(24 * 60 * 60 * 1000);
            let certificate = server.issue(
                &address,
                &identity.identity_key().serialize(),
                expiration.epoch_millis(),
            )?;
            let trust_root = server.trust_root();
            let sessions = Self::sessions(&address, &db, &trust_root, &certificate)?;
            Ok(Self {
                address,
                path,
                db,
                trust_root,
                certificate,
                sessions,
            })
        }

        fn sessions(
            address: &Address,
            db: &Arc<Database>,
            trust_root: &[u8],
            certificate: &[u8],
        ) -> Result<LibsignalSessions<SqliteStores>, Box<dyn Error>> {
            let mut sessions = LibsignalSessions::new(
                address.clone(),
                TrustRoot::new(trust_root)?,
                SqliteStores::new(db.clone()),
            );
            ready(sessions.set_sender_certificate(certificate))??;
            Ok(sessions)
        }

        /// Reabre o banco do arquivo, como um app reiniciado ou a extensão de notificação.
        fn reopen(&mut self) -> TestResult {
            self.db = Arc::new(Database::open(&self.path, &key()?)?);
            self.sessions =
                Self::sessions(&self.address, &self.db, &self.trust_root, &self.certificate)?;
            Ok(())
        }

        /// O mesmo dispositivo aberto por outro processo, como a extensão de notificação: outra
        /// conexão ao mesmo arquivo.
        fn other_process(&self) -> Result<Self, Box<dyn Error>> {
            let db = Arc::new(Database::open(&self.path, &key()?)?);
            Ok(Self {
                sessions: Self::sessions(&self.address, &db, &self.trust_root, &self.certificate)?,
                address: self.address.clone(),
                path: self.path.clone(),
                db,
                trust_root: self.trust_root.clone(),
                certificate: self.certificate.clone(),
            })
        }

        fn store(&self) -> SqliteStore {
            SqliteStore::new(self.db.clone())
        }

        fn encrypt(&mut self, to: &Device, plaintext: &[u8]) -> Result<Ciphertext, Box<dyn Error>> {
            Ok(ready(self.sessions.encrypt(&to.address, plaintext))??)
        }

        fn kind(&mut self, envelope: &Ciphertext) -> Result<CiphertextKind, Box<dyn Error>> {
            Ok(ready(self.sessions.inner_kind(envelope))??)
        }

        fn decrypt(
            &mut self,
            from: &Device,
            envelope: &Ciphertext,
        ) -> Result<Result<Vec<u8>, ProtocolError>, Box<dyn Error>> {
            self.decrypt_then(envelope, |decrypted| {
                assert_eq!(decrypted.from, from.address);
                Ok(decrypted.plaintext.to_vec())
            })
        }

        /// Decifra e entrega a `deliver` dentro da transação.
        fn decrypt_then<T>(
            &mut self,
            envelope: &Ciphertext,
            deliver: impl FnOnce(Decrypted) -> Result<T, ProtocolError>,
        ) -> Result<Result<T, ProtocolError>, Box<dyn Error>> {
            let now = certificate::now()?.epoch_millis();
            Ok(ready(self.sessions.decrypt(envelope, now, deliver))?)
        }
    }

    #[test]
    fn sessao_sobrevive_a_reabrir_o_banco() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut alice, mut bob, first) = alice_and_bob(dir.path())?;
        assert_eq!(bob.kind(&first)?, CiphertextKind::PreKey);

        bob.reopen()?;
        assert_eq!(bob.decrypt(&alice, &first)??, b"oi, bob");
        // Pré-chaves descartáveis consumidas pelo PQXDH.
        assert!(ready(bob.store().get_pre_key(1.into()))?.is_err());
        assert!(ready(bob.store().get_kyber_pre_key(1.into()))?.is_err());

        bob.reopen()?;
        let reply = bob.encrypt(&alice, b"oi, alice")?;
        alice.reopen()?;
        assert_eq!(alice.decrypt(&bob, &reply)??, b"oi, alice");

        let next = alice.encrypt(&bob, b"tudo bem?")?;
        assert_eq!(bob.kind(&next)?, CiphertextKind::Message);
        bob.reopen()?;
        assert_eq!(bob.decrypt(&alice, &next)??, b"tudo bem?");
        assert!(bob.decrypt(&alice, &first)?.is_err(), "replay do PQXDH");
        Ok(())
    }

    /// Alice abre sessão com Bob e manda a primeira mensagem, que carrega o PQXDH.
    fn alice_and_bob(dir: &Path) -> Result<(Device, Device, Ciphertext), Box<dyn Error>> {
        let server = CertificateIssuer::new()?;
        let mut alice = Device::new(dir, 0xA1, &server)?;
        let bob = Device::new(dir, 0xB0, &server)?;
        let bundle =
            testing::publish_bundle(SqliteStores::new(bob.db.clone()).parts(), &bob.address)?;
        ready(alice.sessions.start_session(&bob.address, &bundle))??;
        let first = alice.encrypt(&bob, b"oi, bob")?;
        Ok((alice, bob, first))
    }

    #[test]
    fn entrega_que_falha_desfaz_o_decrypt_inteiro() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, mut bob, first) = alice_and_bob(dir.path())?;
        let alice_address = alice.address.0.clone();

        // A libsignal já gravou sessão, identidade e consumo das pré-chaves quando a entrega
        // falha; nada disso pode ficar.
        let result = bob.decrypt_then(&first, |_| Err::<(), _>(ProtocolError::Internal))?;
        assert_eq!(result, Err(ProtocolError::Internal));
        let store = bob.store();
        assert!(ready(store.load_session(&alice_address))??.is_none());
        assert!(ready(store.get_identity(&alice_address))??.is_none());
        ready(store.get_pre_key(1.into()))??;
        ready(store.get_kyber_pre_key(1.into()))??;

        assert_eq!(bob.decrypt(&alice, &first)??, b"oi, bob");
        assert!(ready(store.load_session(&alice_address))??.is_some());
        assert!(ready(store.get_pre_key(1.into()))?.is_err());
        Ok(())
    }

    #[test]
    fn app_e_extensao_avancam_o_mesmo_ratchet_em_vez() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (mut alice, mut app, first) = alice_and_bob(dir.path())?;
        let second = alice.encrypt(&app, b"tudo bem?")?;
        let mut extension = app.other_process()?;

        assert_eq!(extension.decrypt(&alice, &first)??, b"oi, bob");
        assert_eq!(app.decrypt(&alice, &second)??, b"tudo bem?");
        assert_eq!(
            extension.decrypt(&alice, &first)?,
            Err(ProtocolError::DuplicateMessage)
        );
        Ok(())
    }

    #[test]
    fn ratchet_preso_por_outro_processo_falha_com_busy() -> TestResult {
        let dir = tempfile::tempdir()?;
        let (alice, mut bob, first) = alice_and_bob(dir.path())?;
        let mut db = Database::open(&bob.path, &key()?)?;
        db.set_timeout(std::time::Duration::from_millis(50))?;
        bob.db = Arc::new(db);
        bob.sessions = Device::sessions(&bob.address, &bob.db, &bob.trust_root, &bob.certificate)?;

        let extension = Database::open(&bob.path, &key()?)?;
        extension.begin()?;
        assert_eq!(bob.decrypt(&alice, &first)?, Err(ProtocolError::Busy));
        extension.rollback()?;
        assert_eq!(bob.decrypt(&alice, &first)??, b"oi, bob");
        Ok(())
    }
}
