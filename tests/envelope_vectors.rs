//! Vetores de envelope para os testes de contrato do falaai-server.
//!
//! Uma conversa real entre dois cores gera os ciphertexts. Cada um vira um `Envelope` do
//! falaai-proto, embrulhado no `Frame` `Send` que o remetente manda e no `Deliver` que o
//! destinatário recebe. O contrato do servidor: o envelope do `Deliver` é byte a byte o do
//! `Send`. Formato e uso em `vectors/envelope/README.md`.
//!
//! Os ciphertexts são aleatórios, então os arquivos versionados só mudam quando regerados de
//! propósito, com `make vectors`. No resto do tempo o teste confere os arquivos versionados e
//! que o gerador ainda produz o mesmo formato: casos, campos e versão do selo.

mod common;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use common::{Device, TestResult};
use falaai_core::api::test_support::SealedKind;
use prost::Message as _;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Com esta variável definida, o teste regrava os vetores antes de conferi-los.
const UPDATE: &str = "FALAAI_UPDATE_VECTORS";

/// Schema espelhado em [`proto`].
const PROTO_SOURCE: &str = "github.com/falaai-br/falaai-proto@57fa36c proto/falaai/v1";

/// O que vai em `Envelope.content`: a `UnidentifiedSenderMessage` (sealed sender v1) da
/// libsignal, como o core devolve. O remetente só aparece dentro do selo, então o teste exige
/// ausência do remetente nos bytes inteiros, `content` incluído, e ausência do destinatário
/// dentro do `content`.
const CONTENT_FORMAT: &str = "sealed-sender";

/// `server_timestamp` dos `Deliver`: 2026-01-01T00:00:00Z.
const SERVER_TIMESTAMP: u64 = 1_767_225_600_000;

const SENDER_SEED: u8 = 0xA1;
const RECIPIENT_SEED: u8 = 0xB0;

/// Espelho à mão das mensagens de `proto/falaai/v1/{envelope,websocket}.proto` usadas aqui, até
/// o falaai-proto gerar código Rust. O teste de contrato do servidor decodifica os vetores com o
/// código Go gerado do `.proto`, então uma divergência deste espelho falha lá.
mod proto {
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Envelope {
        #[prost(enumeration = "EnvelopeType", tag = "1")]
        pub r#type: i32,
        #[prost(bytes = "vec", tag = "2")]
        pub client_message_id: Vec<u8>,
        #[prost(bytes = "vec", tag = "3")]
        pub content: Vec<u8>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
    #[repr(i32)]
    pub enum EnvelopeType {
        Unspecified = 0,
        Message = 1,
        Receipt = 2,
        CallSignal = 3,
    }

    impl EnvelopeType {
        /// Nome do valor no `.proto`.
        pub fn proto_name(self) -> &'static str {
            match self {
                Self::Unspecified => "ENVELOPE_TYPE_UNSPECIFIED",
                Self::Message => "ENVELOPE_TYPE_MESSAGE",
                Self::Receipt => "ENVELOPE_TYPE_RECEIPT",
                Self::CallSignal => "ENVELOPE_TYPE_CALL_SIGNAL",
            }
        }
    }

    /// Só os campos do oneof que os vetores usam; os outros cairiam em campo desconhecido.
    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Frame {
        #[prost(oneof = "Payload", tags = "1, 3")]
        pub payload: Option<Payload>,
    }

    #[derive(Clone, PartialEq, prost::Oneof)]
    pub enum Payload {
        #[prost(message, tag = "1")]
        Send(Send),
        #[prost(message, tag = "3")]
        Deliver(Deliver),
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Send {
        #[prost(bytes = "vec", tag = "1")]
        pub destination_aci: Vec<u8>,
        #[prost(uint32, tag = "2")]
        pub destination_device_id: u32,
        #[prost(message, optional, tag = "3")]
        pub envelope: Option<Envelope>,
    }

    #[derive(Clone, PartialEq, prost::Message)]
    pub struct Deliver {
        #[prost(uint64, tag = "1")]
        pub seq: u64,
        #[prost(uint64, tag = "2")]
        pub server_timestamp: u64,
        #[prost(message, optional, tag = "3")]
        pub envelope: Option<Envelope>,
    }
}

use proto::EnvelopeType;

/// Um caso: o que o remetente cifra e como o envelope é rotulado.
struct Case {
    name: &'static str,
    description: &'static str,
    envelope_type: EnvelopeType,
    plaintext: &'static [u8],
}

/// Na ordem da conversa: o primeiro abre a sessão (PreKey); Bob responde antes do segundo, então
/// os seguintes já são da sessão confirmada.
const CASES: [Case; 4] = [
    Case {
        name: "prekey",
        description: "Primeira mensagem da sessão: carrega o material do PQXDH",
        envelope_type: EnvelopeType::Message,
        plaintext: b"oi, bob",
    },
    Case {
        name: "message",
        description: "Mensagem de conversa numa sessão confirmada",
        envelope_type: EnvelopeType::Message,
        plaintext: b"tudo bem?",
    },
    Case {
        name: "receipt",
        description: "Recibo de leitura",
        envelope_type: EnvelopeType::Receipt,
        plaintext: b"lido",
    },
    Case {
        name: "call_signal",
        description: "Sinalização de chamada (oferta SDP)",
        envelope_type: EnvelopeType::CallSignal,
        plaintext: b"v=0",
    },
];

/// Arquivos de um caso, pelo papel no manifesto.
type Files = BTreeMap<&'static str, Vec<u8>>;

/// Vetores gerados: o manifesto e os arquivos de cada caso.
struct Vectors {
    manifest: Value,
    files: BTreeMap<String, Vec<u8>>,
}

/// Alice abre sessão com Bob e manda um envelope por caso. Bob decifra todos, o que garante que
/// são envelopes selados válidos, e responde depois do primeiro para confirmar a sessão.
fn generate() -> Result<Vectors, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let alice = Device::register(dir.path(), SENDER_SEED)?;
    let mut bob = Device::register(dir.path(), RECIPIENT_SEED)?;
    alice.start_session(&mut bob)?;

    let destination_aci = Uuid::parse_str(&bob.address.aci)?.into_bytes().to_vec();
    let mut cases = Vec::new();
    let mut files = BTreeMap::new();
    for (index, case) in CASES.iter().enumerate() {
        let ciphertext = alice.send(&bob, case.plaintext)?;
        assert_eq!(
            bob.kind(&ciphertext)? == SealedKind::PreKey,
            index == 0,
            "{}",
            case.name
        );
        assert_eq!(bob.receive(&alice, ciphertext.clone())?, case.plaintext);
        if index == 0 {
            alice.receive(&bob, bob.send(&alice, b"oi, alice")?)?;
        }

        let seq = u64::try_from(index)? + 1;
        let envelope = proto::Envelope {
            r#type: case.envelope_type.into(),
            client_message_id: client_message_id(seq).to_vec(),
            content: ciphertext.body.clone(),
        };
        let send = proto::Frame {
            payload: Some(proto::Payload::Send(proto::Send {
                destination_aci: destination_aci.clone(),
                destination_device_id: bob.address.device_id.into(),
                envelope: Some(envelope.clone()),
            })),
        };
        let deliver = proto::Frame {
            payload: Some(proto::Payload::Deliver(proto::Deliver {
                seq,
                server_timestamp: SERVER_TIMESTAMP,
                envelope: Some(envelope.clone()),
            })),
        };
        let case_files: Files = [
            ("envelope", envelope.encode_to_vec()),
            ("send", send.encode_to_vec()),
            ("deliver", deliver.encode_to_vec()),
        ]
        .into();

        let mut manifest_files = serde_json::Map::new();
        for (role, bytes) in &case_files {
            let path = format!("{}.{role}.bin", case.name);
            manifest_files.insert(
                (*role).to_owned(),
                json!({ "path": path, "sha256": sha256(bytes) }),
            );
            files.insert(path, bytes.clone());
        }
        cases.push(json!({
            "name": case.name,
            "description": case.description,
            "envelope_type": case.envelope_type.proto_name(),
            "content_format": CONTENT_FORMAT,
            "content_version": ciphertext.body.first().ok_or("envelope vazio")?,
            "client_message_id": hex(&envelope.client_message_id),
            "destination_aci": bob.address.aci,
            "destination_device_id": bob.address.device_id,
            "seq": seq,
            "server_timestamp": SERVER_TIMESTAMP,
            "files": manifest_files,
        }));
    }

    let manifest = json!({
        "description": "Vetores de envelope do falaai-core para os testes de contrato do servidor. Ver README.md.",
        "proto": PROTO_SOURCE,
        "cases": cases,
    });
    Ok(Vectors { manifest, files })
}

/// `client_message_id` do caso `seq`: UUID v4 fixo, para o diff dos vetores mostrar só o que
/// muda de verdade.
fn client_message_id(seq: u64) -> [u8; 16] {
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0000 | u128::from(seq)).into_bytes()
}

fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/envelope")
}

/// Regrava `dir` com os vetores gerados, apagando os `.bin` de casos que sumiram.
fn write(dir: &Path, vectors: &Vectors) -> TestResult {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "bin") {
            fs::remove_file(path)?;
        }
    }
    for (path, bytes) in &vectors.files {
        fs::write(dir.join(path), bytes)?;
    }
    let manifest = serde_json::to_string_pretty(&vectors.manifest)? + "\n";
    fs::write(dir.join("manifest.json"), manifest)?;
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(key)
        .ok_or_else(|| format!("manifesto sem `{key}`").into())
}

fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| format!("`{key}` não é texto").into())
}

fn u64_field(value: &Value, key: &str) -> Result<u64, Box<dyn Error>> {
    field(value, key)?
        .as_u64()
        .ok_or_else(|| format!("`{key}` não é inteiro").into())
}

/// Decodifica `bytes` e exige que recodificar dê os mesmos bytes: sem campo desconhecido, que o
/// prost descartaria em silêncio, e na codificação canônica.
fn decode<M: prost::Message + Default>(bytes: &[u8]) -> Result<M, Box<dyn Error>> {
    let message = M::decode(bytes)?;
    if message.encode_to_vec() != bytes {
        return Err("recodificar não reproduz os bytes".into());
    }
    Ok(message)
}

/// Falha se `bytes` carregam o ACI de `seed`, em texto ou nos 16 bytes do UUID.
fn assert_no_aci(bytes: &[u8], seed: u8, what: &str) -> TestResult {
    let aci = common::aci(seed);
    for needle in [aci.as_bytes(), &Uuid::parse_str(&aci)?.into_bytes()[..]] {
        assert!(!bytes.windows(needle.len()).any(|w| w == needle), "{what}");
    }
    Ok(())
}

/// Falha se `message` carrega o ACI do remetente, inclusive dentro do `content`.
fn assert_no_sender(message: &impl prost::Message, case: &str) -> TestResult {
    assert_no_aci(
        &message.encode_to_vec(),
        SENDER_SEED,
        &format!("{case}: remetente em claro"),
    )
}

/// Confere a consistência de um conjunto de vetores; `read` lê um arquivo pelo nome.
fn check(manifest: &Value, read: impl Fn(&str) -> Result<Vec<u8>, Box<dyn Error>>) -> TestResult {
    let cases = field(manifest, "cases")?
        .as_array()
        .ok_or("`cases` não é lista")?;
    assert_eq!(cases.len(), CASES.len());

    for case in cases {
        let name = str_field(case, "name")?;
        let mut files = BTreeMap::new();
        for (role, file) in field(case, "files")?
            .as_object()
            .ok_or("`files` não é objeto")?
        {
            let bytes = read(str_field(file, "path")?)?;
            assert_eq!(sha256(&bytes), str_field(file, "sha256")?, "{name}.{role}");
            files.insert(role.as_str(), bytes);
        }
        let envelope_bytes = files.get("envelope").ok_or("sem envelope")?;

        let envelope: proto::Envelope = decode(envelope_bytes)?;
        assert_eq!(str_field(case, "content_format")?, CONTENT_FORMAT, "{name}");
        assert_no_sender(&envelope, name)?;
        assert_no_aci(
            &envelope.content,
            RECIPIENT_SEED,
            &format!("{name}: destinatário em claro no `content`"),
        )?;
        assert_eq!(
            EnvelopeType::try_from(envelope.r#type)?.proto_name(),
            str_field(case, "envelope_type")?,
            "{name}"
        );
        assert_eq!(
            hex(&envelope.client_message_id),
            str_field(case, "client_message_id")?
        );
        assert_eq!(envelope.client_message_id.len(), 16, "{name}");
        assert_eq!(
            envelope.content.first().map(|&b| u64::from(b)),
            Some(u64_field(case, "content_version")?),
            "{name}"
        );

        let send = match decode::<proto::Frame>(files.get("send").ok_or("sem send")?)?.payload {
            Some(proto::Payload::Send(send)) => send,
            _ => return Err(format!("{name}.send não é Frame.send").into()),
        };
        assert_no_sender(&send, name)?;
        assert_eq!(
            Uuid::from_slice(&send.destination_aci)?.to_string(),
            str_field(case, "destination_aci")?
        );
        assert_eq!(
            u64::from(send.destination_device_id),
            u64_field(case, "destination_device_id")?
        );
        assert_eq!(
            &send.envelope.ok_or("Send sem envelope")?.encode_to_vec(),
            envelope_bytes,
            "{name}: envelope do Send"
        );

        let deliver =
            match decode::<proto::Frame>(files.get("deliver").ok_or("sem deliver")?)?.payload {
                Some(proto::Payload::Deliver(deliver)) => deliver,
                _ => return Err(format!("{name}.deliver não é Frame.deliver").into()),
            };
        assert_no_sender(&deliver, name)?;
        assert_eq!(deliver.seq, u64_field(case, "seq")?);
        assert_eq!(
            deliver.server_timestamp,
            u64_field(case, "server_timestamp")?
        );
        assert_eq!(
            &deliver
                .envelope
                .ok_or("Deliver sem envelope")?
                .encode_to_vec(),
            envelope_bytes,
            "{name}: envelope do Deliver"
        );
    }
    Ok(())
}

/// O manifesto sem os hashes, que mudam a cada geração.
fn shape(manifest: &Value) -> Value {
    let mut shape = manifest.clone();
    if let Some(cases) = shape.get_mut("cases").and_then(Value::as_array_mut) {
        for files in cases.iter_mut().filter_map(|c| c.get_mut("files")) {
            for file in files
                .as_object_mut()
                .into_iter()
                .flat_map(|f| f.values_mut())
            {
                if let Some(file) = file.as_object_mut() {
                    file.remove("sha256");
                }
            }
        }
    }
    shape
}

#[test]
fn vetores_de_envelope_batem_com_o_gerador() -> TestResult {
    let fresh = generate()?;
    check(&fresh.manifest, |path| {
        Ok(fresh.files.get(path).ok_or("arquivo não gerado")?.clone())
    })?;

    let dir = vectors_dir();
    if std::env::var_os(UPDATE).is_some() {
        write(&dir, &fresh)?;
    }
    let committed: Value = serde_json::from_slice(&fs::read(dir.join("manifest.json"))?)?;
    check(&committed, |path| Ok(fs::read(dir.join(path))?))?;
    assert_eq!(
        shape(&committed),
        shape(&fresh.manifest),
        "o gerador mudou o formato dos vetores: rode `make vectors` e revise o diff"
    );
    Ok(())
}
