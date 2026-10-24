//! E2E headless da Fase 0 (flc-uf0): dois cores contra o falaai-server real, com o falaai-signer,
//! o Postgres e o Redis do compose do servidor. Roda com `make test-e2e`, que sobe o stack e
//! passa o endereço por variáveis de ambiente; fora dele o teste fica ignorado.
//!
//! O app faz em Dart o registro, o upload do bundle e o fetch do bundle de um contato; aqui o
//! teste faz essas chamadas HTTP no lugar dele. Todo o resto é a API pública do núcleo: socket
//! autenticado, socket não autenticado, certificado do `accounts`, cifrar, decifrar, gravar e
//! confirmar.
//!
//! O socket não autenticado (`/v1/ws/unidentified`, fls-o65) pode ainda não estar no servidor.
//! O teste descobre pelo registro da unidentified access key: sem a rota, as mensagens (seladas
//! do mesmo jeito) vão pelo socket autenticado, o fallback do primeiro contato da ADR-0010.
//! `FALAAI_E2E_REQUIRE_UNIDENTIFIED=1` transforma a falta da rota em falha.
//!
//! Do Postgres, o teste confere o que a ADR-0008 exige da `message_queue`: nenhuma coluna de
//! remetente, nenhum envelope com o ACI de quem enviou e a linha apagada depois do `Ack`.

use std::env;
use std::error::Error;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use falaai_core::api::error::CoreError;
use falaai_core::api::types::{
    AccountKeys, ChatEvent, DeviceAddress, PreKey, PreKeyBundle, ServerConfig, SignedPreKey,
};
use falaai_core::api::{FalaaiCore, generate_db_key};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

type TestResult = Result<(), Box<dyn Error>>;

/// Quanto o teste espera por algo que acontece em segundo plano ou do outro lado da rede.
const WAIT: Duration = Duration::from_secs(20);

/// Código de OTP aceito pelo servidor de desenvolvimento (`FALAAI_DEV_OTP` do compose).
const DEV_OTP: &str = "123456";

/// Colunas da `message_queue`. Uma coluna nova tem de passar por aqui: nenhuma pode guardar o
/// remetente (ADR-0008).
const MESSAGE_QUEUE_COLUMNS: [&str; 6] = [
    "recipient_aci",
    "recipient_device",
    "seq",
    "envelope",
    "server_ts",
    "expires_at",
];

const ALICE_PROFILE_KEY: [u8; 32] = [0xA1; 32];
const BOB_PROFILE_KEY: [u8; 32] = [0xB0; 32];

#[test]
#[ignore = "exige o falaai-server no Docker: make test-e2e"]
fn dois_cores_trocam_mensagens_seladas_pelo_servidor_real() -> TestResult {
    let server = Server::from_env()?;
    let dir = tempfile::tempdir()?;
    let alice = Client::register(&server, dir.path(), "alice")?;
    let bob = Client::register(&server, dir.path(), "bob")?;

    // Cada um registra a access key da própria profile key e recebe a do outro, o que a troca
    // de profile key dentro do conteúdo E2EE fará quando existir.
    let alice_sealed = alice.register_access_key(&ALICE_PROFILE_KEY)?;
    let sealed = bob.register_access_key(&BOB_PROFILE_KEY)? && alice_sealed;
    if !sealed && env::var("FALAAI_E2E_REQUIRE_UNIDENTIFIED").as_deref() == Ok("1") {
        return Err("servidor sem o socket não autenticado (fls-o65)".into());
    }
    eprintln!(
        "e2e: envio pelo socket {}",
        if sealed {
            "não autenticado"
        } else {
            "autenticado (servidor sem fls-o65)"
        }
    );
    if sealed {
        alice
            .core
            .set_peer_profile_key(&bob.address, &BOB_PROFILE_KEY)?;
        bob.core
            .set_peer_profile_key(&alice.address, &ALICE_PROFILE_KEY)?;
    }

    // Alice conecta, pega o certificado de remetente no accounts e abre sessão com Bob pelo
    // bundle publicado. Bob segue desconectado: o envelope tem de esperar na fila.
    alice.connect(&alice.token)?;
    alice.renew_sender_certificate()?;
    let bundle = alice.fetch_bundle(&bob.address)?;
    alice
        .core
        .process_prekey_bundle(bob.address.clone(), bundle)?;

    if sealed {
        // Com o token errado o socket autenticado nunca conecta: se a mensagem chegar, foi pelo
        // não autenticado, sem credencial nenhuma de Alice.
        alice.connect("token-recusado")?;
        alice.send(&bob, b"oi, bob")?;
        alice.connect(&alice.token)?;
    } else {
        alice.send(&bob, b"oi, bob")?;
    }

    let queued = server.postgres.envelopes_for(&bob.address)?;
    assert_eq!(
        queued.len(),
        1,
        "envelope de Alice não ficou na fila de Bob"
    );
    server.postgres.assert_no_sender_column()?;
    assert_no_sender(&queued, &alice.address)?;

    // Bob conecta e recebe o pendente: decifra, grava, entrega o evento e confirma.
    bob.connect(&bob.token)?;
    bob.expect_message(&alice, b"oi, bob")?;
    server.postgres.wait_empty(&bob.address)?;
    let stored = bob.core.received_messages(0, u32::MAX)?;
    assert_eq!(stored.len(), 1);
    let first = stored.first().ok_or("mensagem não gravada")?;
    assert_eq!(first.from, alice.address);
    assert_eq!(first.body, b"oi, bob");

    // Bob responde com Alice conectada: entrega na hora, pelo pub/sub do pod de Alice.
    bob.renew_sender_certificate()?;
    bob.send(&alice, b"oi, alice")?;
    alice.expect_message(&bob, b"oi, alice")?;
    server.postgres.wait_empty(&alice.address)?;

    // E a conversa segue na sessão já confirmada.
    alice.send(&bob, b"tudo bem?")?;
    bob.expect_message(&alice, b"tudo bem?")?;
    server.postgres.wait_empty(&bob.address)?;
    Ok(())
}

/// O stack do compose, das variáveis que `scripts/e2e` exporta.
struct Server {
    /// Base HTTP do servidor (`http://127.0.0.1:<porta>`), que também serve o gateway.
    url: String,
    trust_root: Vec<u8>,
    http: ureq::Agent,
    postgres: Postgres,
}

impl Server {
    fn from_env() -> Result<Self, Box<dyn Error>> {
        let var = |name: &str| env::var(name).map_err(|_| format!("{name} ausente: make test-e2e"));
        let http = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(15)))
            .build()
            .new_agent();
        Ok(Self {
            url: var("FALAAI_E2E_URL")?,
            trust_root: STANDARD.decode(var("FALAAI_E2E_TRUST_ROOT")?)?,
            http,
            postgres: Postgres {
                container: var("FALAAI_E2E_POSTGRES")?,
            },
        })
    }

    fn config(&self) -> ServerConfig {
        ServerConfig {
            gateway_url: self.url.replacen("http://", "ws://", 1),
            accounts_url: self.url.clone(),
            root_certificates: Vec::new(),
        }
    }
}

/// Um aparelho: núcleo num banco SQLCipher próprio, registrado no servidor.
struct Client<'a> {
    server: &'a Server,
    core: FalaaiCore,
    address: DeviceAddress,
    token: String,
    events: Receiver<ChatEvent>,
}

#[derive(Deserialize)]
struct Registration {
    aci: String,
    device_id: u8,
    token: String,
}

impl<'a> Client<'a> {
    /// Abre o núcleo, gera as chaves, registra um telefone novo com o OTP de dev, grava o
    /// endereço que o servidor deu e publica o bundle.
    fn register(server: &'a Server, dir: &Path, name: &str) -> Result<Self, Box<dyn Error>> {
        let db_path = dir.join(format!("{name}.db"));
        let core = FalaaiCore::open(
            db_path.to_string_lossy().into_owned(),
            generate_db_key(),
            server.trust_root.clone(),
        )?;
        let keys = core.generate_account_keys()?;

        let phone = format!("+55119{:08}", rand::random::<u32>() % 100_000_000);
        let mut response = server
            .http
            .post(format!("{}/v1/accounts", server.url))
            .send_json(json!({"phone": phone, "code": DEV_OTP, "platform": "android"}))?;
        let status = response.status().as_u16();
        if status != 201 {
            return Err(format!("registro respondeu {status}").into());
        }
        let registration: Registration = response.body_mut().read_json()?;
        let address = DeviceAddress {
            aci: registration.aci,
            device_id: registration.device_id,
        };
        core.set_local_address(address.clone())?;

        let (sender, events) = mpsc::channel();
        core.subscribe_events(move |event| sender.send(event).is_ok());
        let client = Self {
            server,
            core,
            address,
            token: registration.token,
            events,
        };
        client.upload_keys(&keys)?;
        Ok(client)
    }

    fn authorization(&self) -> String {
        let pair = format!(
            "{}.{}:{}",
            self.address.aci, self.address.device_id, self.token
        );
        format!("Basic {}", STANDARD.encode(pair))
    }

    /// `PUT /v1/keys` com a parte pública das chaves da conta.
    fn upload_keys(&self, keys: &AccountKeys) -> TestResult {
        let body = json!({
            "identityKey": STANDARD.encode(&keys.identity_key),
            "registrationId": keys.registration_id,
            "signedPreKey": signed_json(&keys.signed_pre_key),
            "pqLastResortPreKey": signed_json(&keys.kyber_last_resort_pre_key),
            "preKeys": keys.pre_keys.iter().map(|k| json!({
                "keyId": k.id,
                "publicKey": STANDARD.encode(&k.public_key),
            })).collect::<Vec<_>>(),
            "pqPreKeys": keys.kyber_pre_keys.iter().map(signed_json).collect::<Vec<_>>(),
        });
        let response = self
            .server
            .http
            .put(format!("{}/v1/keys", self.server.url))
            .header("Authorization", &self.authorization())
            .send_json(body)?;
        match response.status().as_u16() {
            200 => Ok(()),
            status => Err(format!("upload de chaves respondeu {status}").into()),
        }
    }

    /// `GET /v1/keys/:aci/:device_id`: o bundle de `peer`, consumindo as pré-chaves entregues.
    fn fetch_bundle(&self, peer: &DeviceAddress) -> Result<PreKeyBundle, Box<dyn Error>> {
        let mut response = self
            .server
            .http
            .get(format!(
                "{}/v1/keys/{}/{}",
                self.server.url, peer.aci, peer.device_id
            ))
            .header("Authorization", &self.authorization())
            .call()?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(format!("fetch de bundle respondeu {status}").into());
        }
        let bundle: Value = response.body_mut().read_json()?;
        Ok(PreKeyBundle {
            registration_id: u32::try_from(
                bundle["registrationId"]
                    .as_u64()
                    .ok_or("registrationId ausente")?,
            )?,
            identity_key: bytes(&bundle["identityKey"])?,
            pre_key: match &bundle["preKey"] {
                Value::Null => None,
                key => Some(PreKey {
                    id: key_id(key)?,
                    public_key: bytes(&key["publicKey"])?,
                }),
            },
            signed_pre_key: signed(&bundle["signedPreKey"])?,
            kyber_pre_key: signed(&bundle["pqPreKey"])?,
        })
    }

    /// Registra a access key de `profile_key` na conta. `false` se o servidor não tem a rota,
    /// isto é, ainda não tem o socket não autenticado.
    fn register_access_key(&self, profile_key: &[u8; 32]) -> Result<bool, Box<dyn Error>> {
        let key = falaai_core::api::test_support::unidentified_access_key(profile_key);
        let response = self
            .server
            .http
            .put(format!(
                "{}/v1/accounts/me/unidentified-access",
                self.server.url
            ))
            .header("Authorization", &self.authorization())
            .send_json(json!({"unidentified_access_key": STANDARD.encode(key)}))?;
        match response.status().as_u16() {
            204 => Ok(true),
            404 => Ok(false),
            status => Err(format!("registro da access key respondeu {status}").into()),
        }
    }

    /// Conecta o núcleo ao servidor com `token`; troca a conexão anterior.
    fn connect(&self, token: &str) -> TestResult {
        Ok(self.core.connect(self.server.config(), token.to_owned())?)
    }

    /// Certificado de remetente novo do `accounts`, entregue ao núcleo.
    fn renew_sender_certificate(&self) -> TestResult {
        let certificate = self.core.fetch_sender_certificate()?;
        Ok(self.core.set_sender_certificate(certificate)?)
    }

    /// Cifra, sela e envia `text` a `to`. Enquanto o socket autenticado conecta, o envio por
    /// ele falha com `NotConnected`: tenta de novo até [`WAIT`].
    fn send(&self, to: &Client<'_>, text: &[u8]) -> TestResult {
        let envelope = self.core.encrypt(to.address.clone(), text.to_vec())?;
        let id = rand::random::<[u8; 16]>().to_vec();
        let deadline = Instant::now() + WAIT;
        loop {
            match self
                .core
                .send(to.address.clone(), id.clone(), envelope.clone())
            {
                Err(CoreError::NotConnected) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(100));
                }
                result => return Ok(result?),
            }
        }
    }

    /// A próxima mensagem do stream de eventos é `text`, de `from`.
    fn expect_message(&self, from: &Client<'_>, text: &[u8]) -> TestResult {
        match self.events.recv_timeout(WAIT)? {
            ChatEvent::MessageReceived {
                from: sender, body, ..
            } => {
                assert!(sender == from.address, "remetente errado no evento");
                assert_eq!(body, text);
            }
        }
        Ok(())
    }
}

fn signed_json(key: &SignedPreKey) -> Value {
    json!({
        "keyId": key.id,
        "publicKey": STANDARD.encode(&key.public_key),
        "signature": STANDARD.encode(&key.signature),
    })
}

fn bytes(value: &Value) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(STANDARD.decode(value.as_str().ok_or("campo base64 ausente")?)?)
}

fn key_id(key: &Value) -> Result<u32, Box<dyn Error>> {
    Ok(u32::try_from(
        key["keyId"].as_u64().ok_or("keyId ausente")?,
    )?)
}

fn signed(key: &Value) -> Result<SignedPreKey, Box<dyn Error>> {
    Ok(SignedPreKey {
        id: key_id(key)?,
        public_key: bytes(&key["publicKey"])?,
        signature: bytes(&key["signature"])?,
    })
}

/// Nenhum envelope enfileirado carrega o ACI de `sender`, nem em binário nem em texto.
fn assert_no_sender(envelopes: &[Vec<u8>], sender: &DeviceAddress) -> TestResult {
    let binary = Uuid::parse_str(&sender.aci)?.into_bytes();
    for envelope in envelopes {
        for needle in [&binary[..], sender.aci.as_bytes()] {
            assert!(
                !envelope.windows(needle.len()).any(|w| w == needle),
                "envelope na fila com o ACI do remetente"
            );
        }
    }
    Ok(())
}

/// O Postgres do compose, consultado com o `psql` do próprio container.
struct Postgres {
    container: String,
}

impl Postgres {
    fn query(&self, sql: &str) -> Result<Vec<String>, Box<dyn Error>> {
        let output = Command::new("docker")
            .args([
                "exec",
                &self.container,
                "psql",
                "-U",
                "falaai",
                "-d",
                "falaai",
            ])
            .args(["-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c", sql])
            .output()?;
        if !output.status.success() {
            return Err(format!("psql falhou: {}", String::from_utf8_lossy(&output.stderr)).into());
        }
        Ok(String::from_utf8(output.stdout)?
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Envelopes na fila de `device`, em ordem de chegada.
    fn envelopes_for(&self, device: &DeviceAddress) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
        // O ACI passa pelo parse do UUID antes de entrar no SQL.
        let aci = Uuid::parse_str(&device.aci)?;
        self.query(&format!(
            "SELECT encode(envelope, 'hex') FROM message_queue \
             WHERE recipient_aci = '{aci}' AND recipient_device = {} ORDER BY seq",
            device.device_id
        ))?
        .iter()
        .map(|row| hex(row))
        .collect()
    }

    /// Espera o `Ack` de `device` apagar a fila dele.
    fn wait_empty(&self, device: &DeviceAddress) -> TestResult {
        let deadline = Instant::now() + WAIT;
        while !self.envelopes_for(device)?.is_empty() {
            if Instant::now() > deadline {
                return Err("envelope continua na fila depois do Ack".into());
            }
            thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    fn assert_no_sender_column(&self) -> TestResult {
        let columns = self.query(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = 'message_queue' \
             ORDER BY ordinal_position",
        )?;
        assert_eq!(columns, MESSAGE_QUEUE_COLUMNS);
        Ok(())
    }
}

fn hex(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !text.len().is_multiple_of(2) {
        return Err("hex com tamanho ímpar".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            Ok(u8::from_str_radix(
                text.get(i..i + 2).ok_or("hex inválido")?,
                16,
            )?)
        })
        .collect()
}
