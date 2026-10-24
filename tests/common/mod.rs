//! Dispositivos de teste: um `FalaaiCore` por aparelho, cada um num banco SQLCipher em arquivo,
//! falando só pela API pública, como o app. Um servidor de teste por processo emite os
//! certificados de remetente do sealed sender.
// Cada binário de teste usa só parte disto.
#![allow(dead_code)]

use std::cell::Cell;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use falaai_core::api::FalaaiCore;
use falaai_core::api::error::CoreError;
use falaai_core::api::test_support::{SealedKind, TestAccounts};
use falaai_core::api::types::{AccountKeys, ChatEvent, DeviceAddress, Envelope, PreKeyBundle};

pub type TestResult = Result<(), Box<dyn Error>>;

/// Validade dos certificados de remetente: 24h, como os do `accounts`.
pub const CERTIFICATE_VALIDITY_MILLIS: u64 = 24 * 60 * 60 * 1000;

/// O servidor de teste, com o trust root em que todos os aparelhos confiam.
pub fn accounts() -> Result<&'static TestAccounts, CoreError> {
    static ACCOUNTS: OnceLock<Result<TestAccounts, CoreError>> = OnceLock::new();
    ACCOUNTS
        .get_or_init(TestAccounts::new)
        .as_ref()
        .map_err(|error| *error)
}

/// Agora, em milissegundos desde a época Unix: o `server_timestamp` de uma entrega imediata.
pub fn now_millis() -> Result<u64, Box<dyn Error>> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

/// Um aparelho registrado, com o stream de eventos assinado num canal.
pub struct Device {
    pub address: DeviceAddress,
    seed: u8,
    keys: AccountKeys,
    db_path: PathBuf,
    db_key: Vec<u8>,
    /// Certificado de remetente; fica só em memória no core, então é entregue a cada abertura.
    sender_certificate: Vec<u8>,
    core: FalaaiCore,
    events: Receiver<ChatEvent>,
    /// Próxima pré-chave descartável que o servidor entregaria num fetch do bundle.
    next_pre_key: usize,
    /// A próxima mensagem recebida deve vir com o aviso de identidade trocada
    /// ([`Self::expect_identity_change`]); consumido ao receber.
    expect_identity_change: Cell<bool>,
}

impl Device {
    /// Abre o banco em `dir`, gera as chaves da conta, grava o endereço local e entrega o
    /// certificado de remetente (o que o registro no servidor faria) e assina os eventos. `seed`
    /// distingue os aparelhos.
    pub fn register(dir: &Path, seed: u8) -> Result<Self, Box<dyn Error>> {
        Self::register_file(dir, seed, &format!("{seed:02x}.db"))
    }

    fn register_file(dir: &Path, seed: u8, file: &str) -> Result<Self, Box<dyn Error>> {
        let db_path = dir.join(file);
        let db_key = vec![seed; 32];
        let core = open(&db_path, &db_key)?;
        let keys = core.generate_account_keys()?;
        let address = DeviceAddress {
            aci: aci(seed),
            device_id: 1,
        };
        core.set_local_address(address.clone())?;
        let sender_certificate = accounts()?.issue_sender_certificate(
            &address,
            &keys.identity_key,
            now_millis()? + CERTIFICATE_VALIDITY_MILLIS,
        )?;
        core.set_sender_certificate(sender_certificate.clone())?;
        let events = subscribe(&core);
        Ok(Self {
            address,
            seed,
            keys,
            db_path,
            db_key,
            sender_certificate,
            core,
            events,
            next_pre_key: 0,
            expect_identity_change: Cell::new(false),
        })
    }

    /// O mesmo aparelho reinstalado sem backup: a mesma conta e o mesmo endereço, num banco
    /// novo em `dir`, com identidade nova. Os contatos veem o código de segurança mudar.
    pub fn reinstall(&self, dir: &Path) -> Result<Self, Box<dyn Error>> {
        Self::register_file(dir, self.seed, &format!("{:02x}-reinstalado.db", self.seed))
    }

    /// A próxima mensagem recebida por [`Self::try_receive`] deve trazer `identity_changed`; sem
    /// isto, um aviso de identidade é falha do teste.
    pub fn expect_identity_change(&self) {
        self.expect_identity_change.set(true);
    }

    /// Bundle que o serviço `keys` entregaria agora: consome uma pré-chave EC e uma Kyber
    /// descartáveis a cada chamada.
    pub fn fetch_bundle(&mut self) -> Result<PreKeyBundle, Box<dyn Error>> {
        let index = self.next_pre_key;
        self.next_pre_key += 1;
        Ok(PreKeyBundle {
            registration_id: self.keys.registration_id,
            identity_key: self.keys.identity_key.clone(),
            pre_key: Some(
                self.keys
                    .pre_keys
                    .get(index)
                    .cloned()
                    .ok_or("pré-chaves EC esgotadas")?,
            ),
            signed_pre_key: self.keys.signed_pre_key.clone(),
            kyber_pre_key: self
                .keys
                .kyber_pre_keys
                .get(index)
                .cloned()
                .ok_or("pré-chaves Kyber esgotadas")?,
        })
    }

    /// Abre sessão (PQXDH) com `peer` a partir de um bundle buscado dele. Devolve se a
    /// identidade dele mudou em relação à conhecida.
    pub fn start_session(&self, peer: &mut Device) -> Result<bool, Box<dyn Error>> {
        let bundle = peer.fetch_bundle()?;
        Ok(self
            .core
            .process_prekey_bundle(peer.address.clone(), bundle)?)
    }

    /// Cifra e sela `text` para `to`.
    pub fn send(&self, to: &Device, text: &[u8]) -> Result<Envelope, CoreError> {
        self.core.encrypt(to.address.clone(), text.to_vec())
    }

    /// Tipo da mensagem dentro de um envelope selado para este aparelho.
    pub fn kind(&self, envelope: &Envelope) -> Result<SealedKind, CoreError> {
        self.core.sealed_kind(envelope)
    }

    /// Decifra um envelope que deve vir de `from`, entregue agora. No sucesso, confere que a
    /// mensagem do evento ficou gravada no banco e devolve o texto que chegou no stream de
    /// eventos; na falha, devolve o erro do núcleo e confere que nenhum evento saiu.
    pub fn try_receive(
        &self,
        from: &Device,
        envelope: Envelope,
    ) -> Result<Result<Vec<u8>, CoreError>, Box<dyn Error>> {
        match self.core.decrypt(envelope, Vec::new(), now_millis()?) {
            Ok(()) => match self.events.try_recv()? {
                ChatEvent::MessageReceived {
                    id,
                    from: sender,
                    body,
                    identity_changed,
                } => {
                    if sender != from.address {
                        return Err("evento com remetente errado".into());
                    }
                    let stored = self.core.received_messages(id - 1, 1)?;
                    match stored.first() {
                        Some(m)
                            if m.id == id
                                && m.from == sender
                                && m.body == body
                                && m.identity_changed == identity_changed => {}
                        _ => return Err("mensagem do evento não ficou gravada".into()),
                    }
                    if identity_changed != self.expect_identity_change.replace(false) {
                        return Err(format!(
                            "aviso de identidade inesperado: identity_changed={identity_changed}"
                        )
                        .into());
                    }
                    Ok(Ok(body))
                }
                other => Err(format!("esperava mensagem, veio {other:?}").into()),
            },
            Err(error) => {
                if self.events.try_recv().is_ok() {
                    return Err(format!("evento emitido apesar de {error:?}").into());
                }
                Ok(Err(error))
            }
        }
    }

    /// Como [`Self::try_receive`], exigindo sucesso.
    pub fn receive(&self, from: &Device, envelope: Envelope) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(self.try_receive(from, envelope)??)
    }

    /// O núcleo do aparelho, para o que não tem atalho aqui.
    pub fn core(&self) -> &FalaaiCore {
        &self.core
    }

    /// Chave pública de identidade do aparelho.
    pub fn identity_key(&self) -> &[u8] {
        &self.keys.identity_key
    }

    /// Próxima mensagem que chegar no stream de eventos em até `timeout`, com o remetente.
    pub fn next_message(
        &self,
        timeout: Duration,
    ) -> Result<(DeviceAddress, Vec<u8>), Box<dyn Error>> {
        match self.next_event(timeout)? {
            ChatEvent::MessageReceived { from, body, .. } => Ok((from, body)),
            other => Err(format!("esperava mensagem, veio {other:?}").into()),
        }
    }

    /// Próximo evento que chegar no stream em até `timeout`.
    pub fn next_event(&self, timeout: Duration) -> Result<ChatEvent, Box<dyn Error>> {
        Ok(self.events.recv_timeout(timeout)?)
    }

    /// `true` se nenhum evento está esperando no stream.
    pub fn no_events(&self) -> bool {
        self.events.try_recv().is_err()
    }

    /// O mesmo aparelho aberto por outro processo, como a Notification Service Extension do iOS:
    /// outro núcleo sobre o mesmo banco, com o stream de eventos assinado.
    pub fn other_process(&self) -> Result<Self, Box<dyn Error>> {
        let core = open(&self.db_path, &self.db_key)?;
        core.set_sender_certificate(self.sender_certificate.clone())?;
        let events = subscribe(&core);
        Ok(Self {
            address: self.address.clone(),
            seed: self.seed,
            keys: self.keys.clone(),
            db_path: self.db_path.clone(),
            db_key: self.db_key.clone(),
            sender_certificate: self.sender_certificate.clone(),
            core,
            events,
            next_pre_key: self.next_pre_key,
            expect_identity_change: Cell::new(false),
        })
    }

    /// Fecha e reabre o banco, como o app ao voltar do background ou o NSE do iOS ao acordar.
    pub fn reopen(&mut self) -> TestResult {
        self.reopen_without_events()?;
        self.subscribe();
        Ok(())
    }

    /// Como [`Self::reopen`], mas sem assinar o stream de eventos.
    pub fn reopen_without_events(&mut self) -> TestResult {
        self.core = open(&self.db_path, &self.db_key)?;
        self.core
            .set_sender_certificate(self.sender_certificate.clone())?;
        Ok(())
    }

    /// Assina o stream de eventos de novo.
    pub fn subscribe(&mut self) {
        self.events = subscribe(&self.core);
    }

    /// Fecha o stream de eventos sem tirar o assinante, como o Dart descartando o `StreamSink`:
    /// a próxima entrega falha.
    pub fn close_events(&mut self) {
        self.events = mpsc::channel().1;
    }
}

/// ACI de teste, um UUID v4 válido derivado de `seed`.
pub fn aci(seed: u8) -> String {
    format!("{seed:02x}{seed:02x}{seed:02x}{seed:02x}-0000-4000-8000-000000000000")
}

fn open(path: &Path, key: &[u8]) -> Result<FalaaiCore, CoreError> {
    FalaaiCore::open(
        path.to_string_lossy().into_owned(),
        key.to_vec(),
        accounts()?.trust_root(),
    )
}

fn subscribe(core: &FalaaiCore) -> Receiver<ChatEvent> {
    let (sender, events) = mpsc::channel();
    core.subscribe_events(move |event| sender.send(event).is_ok());
    events
}
