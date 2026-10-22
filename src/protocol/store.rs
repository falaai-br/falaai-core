//! Stores da libsignal sobre o banco local cifrado ([`Database`]).
//!
//! Os registros são guardados no formato serializado da libsignal. Os que carregam segredo
//! (par de identidade, sessões, pré-chaves, sender keys) passam por buffers zerados ao sair de
//! escopo.

use std::sync::Arc;

use async_trait::async_trait;
use libsignal_protocol::{
    CiphertextMessageType, Direction, GenericSignedPreKey, IdentityChange, IdentityKey,
    IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord, KyberPreKeyStore,
    PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, PublicKey, SenderKeyRecord,
    SenderKeyStore, SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId,
    SignedPreKeyRecord, SignedPreKeyStore,
};
use rusqlite::{OptionalExtension, Params, params};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::ProtocolError;
use super::signal::{SignalStores, StoreParts};
use crate::storage::{Database, StorageError};

type SignalResult<T> = Result<T, SignalProtocolError>;

/// Implementa todos os stores da libsignal sobre uma conexão compartilhada. Clonar só copia o
/// handle da conexão.
///
/// Identidades remotas seguem TOFU, como a implementação de referência da libsignal: a primeira
/// vista é confiável; uma diferente da guardada não é, nos dois sentidos, até ser salva.
#[derive(Clone)]
pub(crate) struct SqliteStore {
    db: Arc<Database>,
}

impl SqliteStore {
    /// Stores sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Grava a identidade local, gerada no registro. Falha se já houver uma: trocar a
    /// identidade invalida todas as sessões e não pode acontecer por engano.
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
        Ok(IdentityChange::from_changed(previous.is_some()))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        Ok(self
            .get_identity(address)
            .await?
            .is_none_or(|known| known == *identity))
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
                let tx = c.transaction()?;
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
    sessions: SqliteStore,
    identities: SqliteStore,
    pre_keys: SqliteStore,
    signed_pre_keys: SqliteStore,
    kyber_pre_keys: SqliteStore,
}

impl SqliteStores {
    /// Stores sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        let store = SqliteStore::new(db);
        Self {
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
    use crate::protocol::signal::LibsignalSessions;
    use crate::protocol::testing::{self, ready};
    use crate::protocol::{Address, Envelope, EnvelopeKind, Sessions};
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
    fn identidade_remota_segue_tofu() -> TestResult {
        let mut store = store()?;
        let bob = address(0xB0, 1)?;
        let first = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();
        let second = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();

        assert_eq!(ready(store.get_identity(&bob))??, None);
        assert!(ready(store.is_trusted_identity(
            &bob,
            &first,
            Direction::Sending
        ))??);

        assert_eq!(
            ready(store.save_identity(&bob, &first))??,
            IdentityChange::NewOrUnchanged
        );
        assert_eq!(
            ready(store.save_identity(&bob, &first))??,
            IdentityChange::NewOrUnchanged
        );
        for direction in [Direction::Sending, Direction::Receiving] {
            assert!(ready(store.is_trusted_identity(
                &bob,
                &first,
                direction.clone()
            ))??);
            assert!(!ready(
                store.is_trusted_identity(&bob, &second, direction)
            )??);
        }

        assert_eq!(
            ready(store.save_identity(&bob, &second))??,
            IdentityChange::ReplacedExisting
        );
        assert_eq!(ready(store.get_identity(&bob))??, Some(second));
        assert!(ready(store.is_trusted_identity(
            &bob,
            &second,
            Direction::Sending
        ))??);
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
        sessions: LibsignalSessions<SqliteStores>,
    }

    impl Device {
        fn new(dir: &Path, seed: u8) -> Result<Self, Box<dyn Error>> {
            let path = dir.join(format!("{seed:02x}.db"));
            let db = Arc::new(Database::open(&path, &key()?)?);
            let identity = IdentityKeyPair::generate(&mut rand::rng());
            SqliteStore::new(db.clone()).create_local_identity(&identity, u32::from(seed))?;
            let address = Address::new(&Aci::from_uuid_bytes([seed; 16]).service_id_string(), 1)?;
            Ok(Self {
                sessions: LibsignalSessions::new(address.clone(), SqliteStores::new(db.clone())),
                address,
                path,
                db,
            })
        }

        /// Reabre o banco do arquivo, como um app reiniciado ou a extensão de notificação.
        fn reopen(&mut self) -> TestResult {
            self.db = Arc::new(Database::open(&self.path, &key()?)?);
            self.sessions =
                LibsignalSessions::new(self.address.clone(), SqliteStores::new(self.db.clone()));
            Ok(())
        }

        fn store(&self) -> SqliteStore {
            SqliteStore::new(self.db.clone())
        }

        fn encrypt(&mut self, to: &Device, plaintext: &[u8]) -> Result<Envelope, Box<dyn Error>> {
            Ok(ready(self.sessions.encrypt(&to.address, plaintext))??)
        }

        fn decrypt(
            &mut self,
            from: &Device,
            envelope: &Envelope,
        ) -> Result<Result<Vec<u8>, ProtocolError>, Box<dyn Error>> {
            Ok(ready(self.sessions.decrypt(&from.address, envelope))?.map(|p| p.to_vec()))
        }
    }

    #[test]
    fn sessao_sobrevive_a_reabrir_o_banco() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut alice = Device::new(dir.path(), 0xA1)?;
        let mut bob = Device::new(dir.path(), 0xB0)?;
        let bundle =
            testing::publish_bundle(SqliteStores::new(bob.db.clone()).parts(), &bob.address)?;

        ready(alice.sessions.start_session(&bob.address, &bundle))??;
        let first = alice.encrypt(&bob, b"oi, bob")?;
        assert_eq!(first.kind(), EnvelopeKind::PreKey);

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
        assert_eq!(next.kind(), EnvelopeKind::Message);
        bob.reopen()?;
        assert_eq!(bob.decrypt(&alice, &next)??, b"tudo bem?");
        assert!(bob.decrypt(&alice, &first)?.is_err(), "replay do PQXDH");
        Ok(())
    }
}
