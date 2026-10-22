//! Chaves da conta, geradas no registro. As privadas ficam só no banco local; a parte pública
//! vai ao servidor, que a entrega a quem quiser abrir sessão.

use std::time::SystemTime;

use libsignal_protocol::{
    GenericSignedPreKey, IdentityKeyPair, KeyPair, KyberPreKeyRecord, PreKeyRecord,
    SignalProtocolError, SignedPreKeyRecord, Timestamp, kem,
};
use rand::Rng;

use super::store::{AccountRecords, SqliteStore};
use super::{ProtocolError, PublicPreKey, SignedPublicPreKey};

/// Pré-chaves descartáveis de cada tipo (EC e Kyber) geradas no registro.
pub(crate) const ONE_TIME_PRE_KEYS: u32 = 100;

/// Maior registration id: 14 bits, como no Signal.
const MAX_REGISTRATION_ID: u32 = 0x3FFF;

/// Parte pública das chaves da conta, enviada ao servidor no registro.
pub(crate) struct PublicAccountKeys {
    pub(crate) registration_id: u32,
    pub(crate) identity_key: Vec<u8>,
    pub(crate) signed_pre_key: SignedPublicPreKey,
    /// Kyber de último recurso: usada quando as descartáveis acabam.
    pub(crate) kyber_last_resort_pre_key: SignedPublicPreKey,
    pub(crate) pre_keys: Vec<PublicPreKey>,
    pub(crate) kyber_pre_keys: Vec<SignedPublicPreKey>,
}

/// Gera identidade, registration id, pré-chave assinada, [`ONE_TIME_PRE_KEYS`] pré-chaves
/// descartáveis EC e Kyber e a Kyber de último recurso. Grava tudo em `store` numa transação e
/// devolve só a parte pública. Falha com [`ProtocolError::AccountExists`] se já houver conta.
pub(crate) fn generate_account_keys(
    store: &SqliteStore,
) -> Result<PublicAccountKeys, ProtocolError> {
    let rng = &mut rand::rng();
    let identity = IdentityKeyPair::generate(rng);
    let registration_id = rng.random_range(1..=MAX_REGISTRATION_ID);
    let now = Timestamp::try_from(SystemTime::now()).map_err(|_| ProtocolError::Internal)?;

    let signed = KeyPair::generate(rng);
    let signature = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), rng)
        .map_err(SignalProtocolError::from)?;
    let signed_pre_key = SignedPreKeyRecord::new(1.into(), now, &signed, &signature);
    let pre_keys: Vec<_> = (1..=ONE_TIME_PRE_KEYS)
        .map(|id| PreKeyRecord::new(id.into(), &KeyPair::generate(rng)))
        .collect();
    let kyber = |id: u32| {
        KyberPreKeyRecord::generate(kem::KeyType::Kyber1024, id.into(), identity.private_key())
    };
    let kyber_pre_keys = (1..=ONE_TIME_PRE_KEYS)
        .map(kyber)
        .collect::<Result<Vec<_>, _>>()?;
    let kyber_last_resort = kyber(ONE_TIME_PRE_KEYS + 1)?;

    store.create_account(&AccountRecords {
        identity: &identity,
        registration_id,
        signed_pre_key: &signed_pre_key,
        pre_keys: &pre_keys,
        kyber_pre_keys: &kyber_pre_keys,
        kyber_last_resort: &kyber_last_resort,
    })?;

    Ok(PublicAccountKeys {
        registration_id,
        identity_key: identity.identity_key().serialize().into_vec(),
        signed_pre_key: SignedPublicPreKey {
            id: signed_pre_key.id()?.into(),
            public_key: signed_pre_key.public_key()?.serialize().into_vec(),
            signature: signed_pre_key.signature()?,
        },
        kyber_last_resort_pre_key: kyber_public(&kyber_last_resort)?,
        pre_keys: pre_keys
            .iter()
            .map(|record| {
                Ok(PublicPreKey {
                    id: record.id()?.into(),
                    public_key: record.public_key()?.serialize().into_vec(),
                })
            })
            .collect::<Result<_, ProtocolError>>()?,
        kyber_pre_keys: kyber_pre_keys
            .iter()
            .map(kyber_public)
            .collect::<Result<_, _>>()?,
    })
}

fn kyber_public(record: &KyberPreKeyRecord) -> Result<SignedPublicPreKey, ProtocolError> {
    Ok(SignedPublicPreKey {
        id: record.id()?.into(),
        public_key: record.public_key()?.serialize().into_vec(),
        signature: record.signature()?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::error::Error;
    use std::sync::Arc;

    use libsignal_protocol::{
        IdentityKey, IdentityKeyStore, KyberPreKeyStore, PreKeyStore, PublicKey, SignedPreKeyStore,
    };

    use super::*;
    use crate::protocol::testing::ready;
    use crate::storage::{Database, DatabaseKey};

    type TestResult = Result<(), Box<dyn Error>>;

    fn store() -> Result<SqliteStore, Box<dyn Error>> {
        let key = DatabaseKey::from_bytes(&[0x5A; 32])?;
        Ok(SqliteStore::new(Arc::new(Database::open_in_memory(&key)?)))
    }

    #[test]
    fn gera_e_guarda_as_chaves_da_conta() -> TestResult {
        let store = store()?;
        let keys = generate_account_keys(&store)?;

        assert!((1..=MAX_REGISTRATION_ID).contains(&keys.registration_id));
        assert_eq!(
            ready(store.get_local_registration_id())??,
            keys.registration_id
        );
        let identity = ready(store.get_identity_key_pair())??;
        assert_eq!(
            identity.identity_key().serialize().as_ref(),
            keys.identity_key
        );

        let signed = ready(store.get_signed_pre_key(keys.signed_pre_key.id.into()))??;
        assert_eq!(
            signed.public_key()?.serialize().as_ref(),
            keys.signed_pre_key.public_key
        );

        assert_eq!(keys.pre_keys.len(), ONE_TIME_PRE_KEYS as usize);
        assert_eq!(keys.kyber_pre_keys.len(), ONE_TIME_PRE_KEYS as usize);
        for pre_key in &keys.pre_keys {
            let record = ready(store.get_pre_key(pre_key.id.into()))??;
            assert_eq!(
                record.public_key()?.serialize().as_ref(),
                pre_key.public_key
            );
        }
        for kyber in keys
            .kyber_pre_keys
            .iter()
            .chain([&keys.kyber_last_resort_pre_key])
        {
            let record = ready(store.get_kyber_pre_key(kyber.id.into()))??;
            assert_eq!(record.public_key()?.serialize().as_ref(), kyber.public_key);
        }
        Ok(())
    }

    #[test]
    fn ids_das_pre_chaves_nao_se_repetem() -> TestResult {
        let keys = generate_account_keys(&store()?)?;
        let ec: HashSet<_> = keys.pre_keys.iter().map(|k| k.id).collect();
        assert_eq!(ec.len(), keys.pre_keys.len());
        let kyber: HashSet<_> = keys
            .kyber_pre_keys
            .iter()
            .chain([&keys.kyber_last_resort_pre_key])
            .map(|k| k.id)
            .collect();
        assert_eq!(kyber.len(), keys.kyber_pre_keys.len() + 1);
        Ok(())
    }

    #[test]
    fn pre_chaves_publicas_sao_assinadas_pela_identidade() -> TestResult {
        let keys = generate_account_keys(&store()?)?;
        let identity = IdentityKey::decode(&keys.identity_key)?;
        for signed in keys
            .kyber_pre_keys
            .iter()
            .chain([&keys.signed_pre_key, &keys.kyber_last_resort_pre_key])
        {
            assert!(
                identity
                    .public_key()
                    .verify_signature(&signed.public_key, &signed.signature)
            );
        }
        for pre_key in &keys.pre_keys {
            PublicKey::deserialize(&pre_key.public_key)?;
        }
        Ok(())
    }

    #[test]
    fn parte_publica_nao_carrega_chave_privada() -> TestResult {
        let store = store()?;
        let keys = generate_account_keys(&store)?;

        let mut private = vec![
            ready(store.get_identity_key_pair())??
                .private_key()
                .serialize(),
            ready(store.get_signed_pre_key(keys.signed_pre_key.id.into()))??
                .private_key()?
                .serialize(),
        ];
        for pre_key in &keys.pre_keys {
            private.push(
                ready(store.get_pre_key(pre_key.id.into()))??
                    .private_key()?
                    .serialize(),
            );
        }
        for kyber in keys
            .kyber_pre_keys
            .iter()
            .chain([&keys.kyber_last_resort_pre_key])
        {
            private.push(
                ready(store.get_kyber_pre_key(kyber.id.into()))??
                    .secret_key()?
                    .serialize()
                    .into_vec(),
            );
        }

        let public = [&keys.identity_key]
            .into_iter()
            .chain(keys.pre_keys.iter().map(|k| &k.public_key))
            .chain(
                keys.kyber_pre_keys
                    .iter()
                    .chain([&keys.signed_pre_key, &keys.kyber_last_resort_pre_key])
                    .flat_map(|k| [&k.public_key, &k.signature]),
            )
            .collect::<Vec<_>>();
        for secret in &private {
            assert!(secret.len() >= 32);
            for bytes in &public {
                assert!(
                    !bytes.windows(secret.len()).any(|w| w == secret.as_slice()),
                    "chave privada na parte pública"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn segunda_geracao_falha_e_mantem_a_primeira() -> TestResult {
        let store = store()?;
        let first = generate_account_keys(&store)?;
        assert!(matches!(
            generate_account_keys(&store),
            Err(ProtocolError::AccountExists)
        ));
        let identity = ready(store.get_identity_key_pair())??;
        assert_eq!(
            identity.identity_key().serialize().as_ref(),
            first.identity_key
        );
        let signed = ready(store.get_signed_pre_key(first.signed_pre_key.id.into()))??;
        assert_eq!(
            signed.public_key()?.serialize().as_ref(),
            first.signed_pre_key.public_key
        );
        Ok(())
    }
}
