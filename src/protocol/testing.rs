//! Apoio aos testes do protocolo, comum aos stores em memória e ao SQLite.

use std::error::Error;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use libsignal_protocol::{
    GenericSignedPreKey, KeyPair, KyberPreKeyRecord, PreKeyRecord, SignedPreKeyRecord, Timestamp,
    kem,
};

use super::signal::StoreParts;
use super::{Address, PeerBundle};

/// Os stores em memória e o SQLite nunca suspendem: um único poll conclui o futuro.
pub(crate) fn ready<F: Future>(future: F) -> Result<F::Output, &'static str> {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => Err("futuro pendente com stores síncronos"),
    }
}

/// Gera pré-chaves (EC descartável, EC assinada e Kyber) com id 1, guarda as privadas em
/// `stores` e devolve o bundle público de `address`, como seria publicado no servidor.
pub(crate) fn publish_bundle(
    stores: StoreParts<'_>,
    address: &Address,
) -> Result<PeerBundle, Box<dyn Error>> {
    let rng = &mut rand::rng();
    let identity = ready(stores.identities.get_identity_key_pair())??;
    let registration_id = ready(stores.identities.get_local_registration_id())??;

    let pre_key = KeyPair::generate(rng);
    let signed = KeyPair::generate(rng);
    let signed_signature = identity
        .private_key()
        .calculate_signature(&signed.public_key.serialize(), rng)?;
    let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, rng);
    let kyber_signature = identity
        .private_key()
        .calculate_signature(&kyber.public_key.serialize(), rng)?;

    ready(
        stores
            .pre_keys
            .save_pre_key(1.into(), &PreKeyRecord::new(1.into(), &pre_key)),
    )??;
    ready(stores.signed_pre_keys.save_signed_pre_key(
        1.into(),
        &SignedPreKeyRecord::new(
            1.into(),
            Timestamp::from_epoch_millis(0),
            &signed,
            &signed_signature,
        ),
    ))??;
    ready(stores.kyber_pre_keys.save_kyber_pre_key(
        1.into(),
        &KyberPreKeyRecord::new(
            1.into(),
            Timestamp::from_epoch_millis(0),
            &kyber,
            &kyber_signature,
        ),
    ))??;

    Ok(PeerBundle(libsignal_protocol::PreKeyBundle::new(
        registration_id,
        address.0.device_id(),
        Some((1.into(), pre_key.public_key)),
        1.into(),
        signed.public_key,
        signed_signature.to_vec(),
        1.into(),
        kyber.public_key,
        kyber_signature.to_vec(),
        *identity.identity_key(),
    )?))
}
