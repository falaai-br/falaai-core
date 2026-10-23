//! Dois cores no mesmo processo, cada um no seu banco SQLCipher, trocando mensagens pela API
//! pública: PQXDH para abrir a sessão, Triple Ratchet a cada mensagem e sealed sender por fora.
//!
//! A entrega do servidor é at-least-once e a ordem não é garantida (03-backend-e-infra): os
//! cenários cobrem mensagens fora de ordem, atrasadas de uma cadeia anterior e duplicadas. Uma
//! duplicada é recusada com `DuplicateMessage`, sem evento, e a sessão segue funcionando.

mod common;

use std::collections::HashSet;
use std::error::Error;

use common::{Device, TestResult};
use falaai_core::api::error::CoreError;
use falaai_core::api::test_support::SealedKind;
use falaai_core::api::types::Envelope;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use rand::{Rng, SeedableRng};

/// Alice e Bob registrados, e Alice com sessão aberta a partir de um bundle de Bob.
fn alice_and_bob(dir: &tempfile::TempDir) -> Result<(Device, Device), Box<dyn Error>> {
    let alice = Device::register(dir.path(), 0xA1)?;
    let mut bob = Device::register(dir.path(), 0xB0)?;
    alice.start_session(&mut bob)?;
    Ok((alice, bob))
}

/// Alice manda a primeira mensagem e Bob responde: a sessão fica confirmada dos dois lados.
fn confirmed_session(dir: &tempfile::TempDir) -> Result<(Device, Device), Box<dyn Error>> {
    let (alice, bob) = alice_and_bob(dir)?;
    bob.receive(&alice, alice.send(&bob, b"oi, bob")?)?;
    alice.receive(&bob, bob.send(&alice, b"oi, alice")?)?;
    Ok((alice, bob))
}

fn texts(prefix: &str, count: usize) -> Vec<Vec<u8>> {
    (0..count)
        .map(|n| format!("{prefix} #{n}").into_bytes())
        .collect()
}

fn send_all(from: &Device, to: &Device, texts: &[Vec<u8>]) -> Result<Vec<Envelope>, CoreError> {
    texts.iter().map(|text| from.send(to, text)).collect()
}

#[test]
fn pqxdh_abre_sessao_e_conversa_nos_dois_sentidos() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = alice_and_bob(&dir)?;

    let first = alice.send(&bob, b"oi, bob")?;
    assert_eq!(bob.kind(&first)?, SealedKind::PreKey);
    assert_eq!(bob.receive(&alice, first)?, b"oi, bob");

    // Cada troca de sentido gira o ratchet; nenhuma mensagem depois da resposta é PreKey.
    for round in 0..5 {
        let from_bob = format!("bob, rodada {round}").into_bytes();
        let reply = bob.send(&alice, &from_bob)?;
        assert_eq!(alice.kind(&reply)?, SealedKind::Message);
        assert_eq!(alice.receive(&bob, reply)?, from_bob);

        let from_alice = format!("alice, rodada {round}").into_bytes();
        let next = alice.send(&bob, &from_alice)?;
        assert_eq!(bob.kind(&next)?, SealedKind::Message);
        assert_eq!(bob.receive(&alice, next)?, from_alice);
    }
    Ok(())
}

#[test]
fn mensagens_fora_de_ordem_na_mesma_cadeia() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = confirmed_session(&dir)?;
    let texts = texts("alice", 5);
    let envelopes = send_all(&alice, &bob, &texts)?;

    for index in [4, 0, 3, 1, 2] {
        assert_eq!(bob.receive(&alice, envelopes[index].clone())?, texts[index]);
    }
    Ok(())
}

#[test]
fn prekey_messages_fora_de_ordem() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = alice_and_bob(&dir)?;
    // Sem resposta de Bob, todas carregam o material do PQXDH.
    let texts = texts("alice", 3);
    let envelopes = send_all(&alice, &bob, &texts)?;
    for envelope in &envelopes {
        assert_eq!(bob.kind(envelope)?, SealedKind::PreKey);
    }

    for index in [2, 0, 1] {
        assert_eq!(bob.receive(&alice, envelopes[index].clone())?, texts[index]);
    }
    let reply = bob.send(&alice, b"recebi as tres")?;
    assert_eq!(alice.receive(&bob, reply)?, b"recebi as tres");
    assert_eq!(
        bob.kind(&alice.send(&bob, b"depois")?)?,
        SealedKind::Message
    );
    Ok(())
}

#[test]
fn mensagem_atrasada_de_uma_cadeia_anterior() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = confirmed_session(&dir)?;
    let early = alice.send(&bob, b"primeira")?;
    let late = alice.send(&bob, b"atrasada")?;
    bob.receive(&alice, early)?;

    // Bob responde e Alice gira o ratchet: a próxima mensagem dela já é de outra cadeia.
    alice.receive(&bob, bob.send(&alice, b"resposta")?)?;
    let next_chain = alice.send(&bob, b"nova cadeia")?;
    assert_eq!(bob.receive(&alice, next_chain)?, b"nova cadeia");
    assert_eq!(bob.receive(&alice, late)?, b"atrasada");
    Ok(())
}

#[test]
fn duplicadas_sao_recusadas_sem_evento_e_sem_quebrar_a_sessao() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = alice_and_bob(&dir)?;
    let first = alice.send(&bob, b"oi, bob")?;
    bob.receive(&alice, first.clone())?;
    assert_eq!(
        bob.try_receive(&alice, first.clone())?,
        Err(CoreError::DuplicateMessage),
        "PreKey repetida"
    );

    let reply = bob.send(&alice, b"oi, alice")?;
    alice.receive(&bob, reply.clone())?;
    assert_eq!(
        alice.try_receive(&bob, reply)?,
        Err(CoreError::DuplicateMessage)
    );

    let next = alice.send(&bob, b"tudo bem?")?;
    assert_eq!(bob.receive(&alice, next.clone())?, b"tudo bem?");
    for _ in 0..2 {
        assert_eq!(
            bob.try_receive(&alice, next.clone())?,
            Err(CoreError::DuplicateMessage)
        );
    }
    // A PreKey original volta depois que a sessão já girou.
    assert_eq!(
        bob.try_receive(&alice, first)?,
        Err(CoreError::DuplicateMessage)
    );

    assert_eq!(bob.receive(&alice, alice.send(&bob, b"segue")?)?, b"segue");
    assert_eq!(alice.receive(&bob, bob.send(&alice, b"segue")?)?, b"segue");
    Ok(())
}

#[test]
fn duplicada_de_mensagem_recebida_fora_de_ordem() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, bob) = confirmed_session(&dir)?;
    let texts = texts("alice", 3);
    let envelopes = send_all(&alice, &bob, &texts)?;

    bob.receive(&alice, envelopes[2].clone())?;
    bob.receive(&alice, envelopes[0].clone())?;
    for index in [2, 0] {
        assert_eq!(
            bob.try_receive(&alice, envelopes[index].clone())?,
            Err(CoreError::DuplicateMessage),
            "#{index}"
        );
    }
    assert_eq!(bob.receive(&alice, envelopes[1].clone())?, texts[1]);
    assert_eq!(
        bob.try_receive(&alice, envelopes[1].clone())?,
        Err(CoreError::DuplicateMessage)
    );
    Ok(())
}

#[test]
fn chaves_puladas_sobrevivem_a_reabrir_o_banco() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (alice, mut bob) = confirmed_session(&dir)?;
    let texts = texts("alice", 3);
    let envelopes = send_all(&alice, &bob, &texts)?;

    bob.receive(&alice, envelopes[2].clone())?;
    bob.reopen()?;
    assert_eq!(bob.receive(&alice, envelopes[0].clone())?, texts[0]);
    bob.reopen()?;
    assert_eq!(
        bob.try_receive(&alice, envelopes[2].clone())?,
        Err(CoreError::DuplicateMessage)
    );
    assert_eq!(bob.receive(&alice, envelopes[1].clone())?, texts[1]);
    Ok(())
}

#[test]
fn sessao_aberta_sobrevive_a_reabrir_os_dois_bancos() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (mut alice, mut bob) = alice_and_bob(&dir)?;
    let first = alice.send(&bob, b"oi, bob")?;
    alice.reopen()?;
    bob.reopen()?;
    assert_eq!(bob.receive(&alice, first)?, b"oi, bob");
    let reply = bob.send(&alice, b"oi, alice")?;
    alice.reopen()?;
    assert_eq!(alice.receive(&bob, reply)?, b"oi, alice");
    Ok(())
}

/// Envelope em trânsito no servidor simulado.
#[derive(Clone)]
struct InFlight {
    /// Índice em `sent`, para conferir o texto e saber se já foi entregue.
    id: usize,
    from: usize,
    envelope: Envelope,
    /// Já ficou uma rodada na fila; não atrasa de novo.
    delayed: bool,
    /// Já foi duplicado; a cópia não duplica de novo.
    duplicated: bool,
}

/// Conversa em rodadas com entrega at-least-once: a cada rodada os dois mandam algumas
/// mensagens, e o servidor entrega as pendentes embaralhadas, duplicando algumas e segurando
/// outras para a rodada seguinte. Toda mensagem chega uma vez como evento; toda cópia extra é
/// recusada como duplicada.
///
/// O atraso fica limitado a uma rodada porque a libsignal guarda poucas cadeias de recepção
/// antigas: uma mensagem que atravessa muitos giros do ratchet é perdida por projeto.
fn embaralhada(seed: u64) -> TestResult {
    const ROUNDS: usize = 12;
    let mut rng = StdRng::seed_from_u64(seed);
    let dir = tempfile::tempdir()?;
    let (alice, bob) = alice_and_bob(&dir)?;
    let devices = [alice, bob];
    let names = ["alice", "bob"];
    // Bob só tem sessão depois de decifrar a primeira mensagem de Alice.
    let mut has_session = [true, false];
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut delivered = HashSet::new();
    let mut duplicates = 0;
    let mut queue: Vec<InFlight> = Vec::new();

    for round in 0..=ROUNDS {
        if round < ROUNDS {
            let mut senders = [0, 1];
            senders.shuffle(&mut rng);
            for from in senders.into_iter().filter(|&from| has_session[from]) {
                for _ in 0..rng.random_range(0..=3) {
                    let text = format!("{} #{} (rodada {round})", names[from], sent.len());
                    let envelope = devices[from].send(&devices[1 - from], text.as_bytes())?;
                    queue.push(InFlight {
                        id: sent.len(),
                        from,
                        envelope,
                        delayed: false,
                        duplicated: false,
                    });
                    sent.push(text.into_bytes());
                }
            }
        }

        let mut batch = Vec::new();
        let mut held = Vec::new();
        for mut item in queue.drain(..) {
            if round < ROUNDS && !item.delayed && rng.random_bool(0.2) {
                item.delayed = true;
                held.push(item);
                continue;
            }
            if !item.duplicated && rng.random_bool(0.25) {
                item.duplicated = true;
                batch.push(item.clone());
            }
            batch.push(item);
        }
        queue = held;
        batch.shuffle(&mut rng);

        for item in batch {
            let (from, to) = (&devices[item.from], &devices[1 - item.from]);
            let result = to.try_receive(from, item.envelope)?;
            if delivered.insert(item.id) {
                assert_eq!(result?, sent[item.id], "semente {seed}, #{}", item.id);
                has_session[1 - item.from] = true;
            } else {
                assert_eq!(
                    result,
                    Err(CoreError::DuplicateMessage),
                    "semente {seed}, #{}",
                    item.id
                );
                duplicates += 1;
            }
        }
    }

    assert!(queue.is_empty());
    assert_eq!(delivered.len(), sent.len(), "semente {seed}");
    assert!(
        sent.len() > ROUNDS && duplicates > 0,
        "semente {seed} gerou pouca coisa: {} mensagens, {duplicates} duplicadas",
        sent.len()
    );
    let [alice, bob] = &devices;
    assert_eq!(bob.receive(alice, alice.send(bob, b"fim")?)?, b"fim");
    assert_eq!(alice.receive(bob, bob.send(alice, b"fim")?)?, b"fim");
    Ok(())
}

#[test]
fn entrega_at_least_once_embaralhada() -> TestResult {
    for seed in [1, 2, 3, 4] {
        embaralhada(seed)?;
    }
    Ok(())
}
