//! Mensagens recebidas gravadas no banco SQLCipher na mesma transação que avança o ratchet.
//!
//! O cenário é o do iOS: a Notification Service Extension abre o mesmo banco que o app, decifra
//! a mensagem da notificação e o evento fica nela. O app só sabe da mensagem pelo banco.

mod common;

use std::error::Error;

use common::{Device, TestResult, now_millis};
use falaai_core::api::error::CoreError;
use falaai_core::api::types::ReceivedMessage;

/// Alice com sessão aberta com Bob e a primeira mensagem dela já recebida pelo app de Bob.
fn alice_and_bob(dir: &tempfile::TempDir) -> Result<(Device, Device), Box<dyn Error>> {
    let alice = Device::register(dir.path(), 0xA1)?;
    let mut bob = Device::register(dir.path(), 0xB0)?;
    alice.start_session(&mut bob)?;
    bob.receive(&alice, alice.send(&bob, b"oi, bob")?)?;
    Ok((alice, bob))
}

fn all(device: &Device) -> Result<Vec<ReceivedMessage>, CoreError> {
    device.core().received_messages(0, u32::MAX)
}

fn bodies(messages: &[ReceivedMessage]) -> Vec<&[u8]> {
    messages.iter().map(|m| m.body.as_slice()).collect()
}

#[test]
fn extensao_decifra_com_o_app_fechado_e_o_app_le_ao_abrir() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, mut app) = alice_and_bob(&dir)?;
    let cursor = all(&app)?.last().ok_or("sem mensagem")?.id;

    let extension = app.other_process()?;
    let texts: [&[u8]; 3] = [b"um", b"dois", b"tres"];
    for text in texts {
        assert_eq!(extension.receive(&alice, alice.send(&app, text)?)?, text);
    }
    drop(extension);

    app.reopen()?;
    let unread = app.core().received_messages(cursor, 10)?;
    assert_eq!(bodies(&unread), texts);
    assert!(unread.iter().all(|m| m.from == alice.address));
    assert!(unread.windows(2).all(|w| w[0].id < w[1].id));
    Ok(())
}

#[test]
fn app_e_extensao_alternando_gravam_tudo_uma_vez_na_ordem_de_gravacao() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, app) = alice_and_bob(&dir)?;
    let extension = app.other_process()?;

    let mut expected: Vec<Vec<u8>> = vec![b"oi, bob".to_vec()];
    for n in 0..6 {
        let text = format!("mensagem {n}").into_bytes();
        let envelope = alice.send(&app, &text)?;
        let receiver = if n % 2 == 0 { &extension } else { &app };
        receiver.receive(&alice, envelope.clone())?;
        // A reentrega ao outro processo é recusada e não grava de novo.
        let other = if n % 2 == 0 { &app } else { &extension };
        assert_eq!(
            other.try_receive(&alice, envelope)?,
            Err(CoreError::DuplicateMessage)
        );
        expected.push(text);
    }
    assert!(app.core().changed_by_other_process()?);

    let stored = all(&app)?;
    assert_eq!(bodies(&stored), expected);

    // Paginado pelo cursor, dá o mesmo.
    let mut paged = Vec::new();
    let mut cursor = 0;
    loop {
        let page = app.core().received_messages(cursor, 2)?;
        let Some(last) = page.last() else { break };
        cursor = last.id;
        paged.extend(page);
    }
    assert_eq!(paged, stored);
    Ok(())
}

#[test]
fn stream_fechado_na_extensao_nao_grava_e_o_app_decifra_a_reentrega() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, app) = alice_and_bob(&dir)?;
    let mut extension = app.other_process()?;
    let before = all(&app)?;

    let envelope = alice.send(&app, b"tudo bem?")?;
    extension.close_events();
    assert_eq!(
        extension.core().decrypt(envelope.clone(), now_millis()?),
        Err(CoreError::NoEventListener)
    );
    assert_eq!(all(&app)?, before);

    assert_eq!(app.receive(&alice, envelope)?, b"tudo bem?");
    assert_eq!(all(&app)?.len(), before.len() + 1);
    Ok(())
}
