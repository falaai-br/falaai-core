//! Safety numbers pela API pública, com bancos SQLCipher em arquivo: os dois aparelhos mostram
//! o mesmo código e conferem o QR um do outro; uma reinstalação troca a identidade, o aviso vai
//! na mensagem em que a troca chegou, e só a conversa verificada bloqueia o envio.

mod common;

use std::error::Error;

use common::{Device, TestResult};
use falaai_core::api::error::CoreError;
use falaai_core::api::types::IdentityStatus;

/// Alice e Bob com sessão aberta e uma mensagem em cada sentido: cada um conhece a identidade
/// do outro.
fn alice_and_bob(dir: &tempfile::TempDir) -> Result<(Device, Device), Box<dyn Error>> {
    let alice = Device::register(dir.path(), 0xA1)?;
    let mut bob = Device::register(dir.path(), 0xB0)?;
    assert!(!alice.start_session(&mut bob)?);
    bob.receive(&alice, alice.send(&bob, b"oi, bob")?)?;
    alice.receive(&bob, bob.send(&alice, b"oi, alice")?)?;
    Ok((alice, bob))
}

#[test]
fn os_dois_aparelhos_mostram_o_mesmo_codigo_e_conferem_o_qr_um_do_outro() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, mut bob) = alice_and_bob(&dir)?;

    let from_alice = alice.core().safety_number(bob.address.clone())?;
    let from_bob = bob.core().safety_number(alice.address.clone())?;
    assert_eq!(from_alice.digits, from_bob.digits);
    assert_eq!(from_alice.digits.len(), 60);
    assert!(from_alice.digits.bytes().all(|b| b.is_ascii_digit()));
    assert!(
        alice
            .core()
            .safety_number_matches(bob.address.clone(), from_bob.qr.clone())?
    );
    assert!(
        bob.core()
            .safety_number_matches(alice.address.clone(), from_alice.qr)?
    );

    // O código sobrevive a reabrir o banco e é por conversa: outro contato tem outro.
    bob.reopen()?;
    assert_eq!(
        bob.core().safety_number(alice.address.clone())?.digits,
        from_bob.digits
    );
    let mut carol = Device::register(dir.path(), 0xC0)?;
    alice.start_session(&mut carol)?;
    assert_ne!(
        alice.core().safety_number(carol.address.clone())?.digits,
        from_alice.digits
    );
    assert!(
        !alice
            .core()
            .safety_number_matches(carol.address.clone(), from_bob.qr)?
    );
    Ok(())
}

#[test]
fn reinstalacao_do_contato_e_avisada_na_mensagem_e_nao_bloqueia_sem_verificacao() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (mut alice, bob) = alice_and_bob(&dir)?;
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Default
    );
    let before = alice.core().safety_number(bob.address.clone())?;

    let bob = bob.reinstall(dir.path())?;
    assert!(!bob.start_session(&mut alice)?);
    alice.expect_identity_change();
    assert_eq!(
        alice.receive(&bob, bob.send(&alice, b"voltei")?)?,
        b"voltei"
    );
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Default
    );
    let after = alice.core().safety_number(bob.address.clone())?;
    assert_ne!(after.digits, before.digits);
    assert_eq!(
        after.digits,
        bob.core().safety_number(alice.address.clone())?.digits
    );

    // Só a mensagem da troca leva o aviso, inclusive relida do banco; e nada é bloqueado.
    assert_eq!(
        alice.receive(&bob, bob.send(&alice, b"tudo bem?")?)?,
        b"tudo bem?"
    );
    assert_eq!(bob.receive(&alice, alice.send(&bob, b"tudo")?)?, b"tudo");
    let flags: Vec<bool> = alice
        .core()
        .received_messages(0, 10)?
        .iter()
        .map(|m| m.identity_changed)
        .collect();
    assert_eq!(flags, [false, true, false]);
    Ok(())
}

#[test]
fn conversa_verificada_bloqueia_o_envio_depois_da_troca_ate_o_usuario_agir() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (mut alice, bob) = alice_and_bob(&dir)?;
    alice
        .core()
        .set_identity_verified(bob.address.clone(), true)?;
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Verified
    );
    assert_eq!(
        bob.receive(&alice, alice.send(&bob, b"verificado")?)?,
        b"verificado"
    );

    let bob = bob.reinstall(dir.path())?;
    bob.start_session(&mut alice)?;
    alice.expect_identity_change();
    alice.receive(&bob, bob.send(&alice, b"voltei")?)?;
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Changed
    );
    assert_eq!(
        alice.send(&bob, b"bloqueada"),
        Err(CoreError::UntrustedIdentity)
    );
    // Receber continua aberto, e a verificação sobrevive a reabrir o banco.
    assert_eq!(
        alice.receive(&bob, bob.send(&alice, b"ainda aqui")?)?,
        b"ainda aqui"
    );
    alice.reopen()?;
    assert_eq!(
        alice.send(&bob, b"bloqueada"),
        Err(CoreError::UntrustedIdentity)
    );

    // Conferido o código novo, verificar de novo libera e volta a proteger.
    let scanned = bob.core().safety_number(alice.address.clone())?.qr;
    assert!(
        alice
            .core()
            .safety_number_matches(bob.address.clone(), scanned)?
    );
    alice
        .core()
        .set_identity_verified(bob.address.clone(), true)?;
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Verified
    );
    assert_eq!(
        bob.receive(&alice, alice.send(&bob, b"liberada")?)?,
        b"liberada"
    );
    Ok(())
}

#[test]
fn bundle_com_identidade_nova_em_conversa_verificada_nao_abre_sessao_mas_mostra_o_codigo_novo()
-> TestResult {
    let dir = tempfile::tempdir()?;
    let (mut alice, bob) = alice_and_bob(&dir)?;
    alice
        .core()
        .set_identity_verified(bob.address.clone(), true)?;

    // O Bob reinstalado conhece a identidade de Alice pelo bundle dela, sem lhe escrever.
    let mut bob = bob.reinstall(dir.path())?;
    assert!(!bob.start_session(&mut alice)?);
    assert_eq!(
        alice.start_session(&mut bob).err().map(|e| e.to_string()),
        Some(CoreError::UntrustedIdentity.to_string())
    );
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Changed
    );
    assert_eq!(
        alice.core().safety_number(bob.address.clone())?.digits,
        bob.core().safety_number(alice.address.clone())?.digits
    );

    // Aceitar a troca sem conferir volta ao padrão; a sessão abre sem nova troca.
    alice
        .core()
        .set_identity_verified(bob.address.clone(), false)?;
    assert_eq!(
        alice.core().identity_status(bob.address.clone())?,
        IdentityStatus::Default
    );
    assert!(!alice.start_session(&mut bob)?);
    assert_eq!(
        bob.receive(&alice, alice.send(&bob, b"agora sim")?)?,
        b"agora sim"
    );
    Ok(())
}
