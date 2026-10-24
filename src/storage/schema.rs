//! Migrações do banco local, aplicadas em ordem e registradas em `PRAGMA user_version`.
//!
//! Só se acrescenta ao fim da lista; uma migração publicada nunca muda.

/// Versão do schema com todas as migrações aplicadas.
pub(super) const VERSION: u32 = MIGRATIONS.len() as u32;

/// Uma entrada por versão: a de índice `i` leva o banco da versão `i` para `i + 1`.
pub(super) const MIGRATIONS: &[&str] = &[
    // 1: stores da libsignal. Registros serializados pela própria libsignal.
    "
    CREATE TABLE local_identity (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        key_pair BLOB NOT NULL,
        registration_id INTEGER NOT NULL
    ) STRICT;

    -- Identidade remota é da conta (ACI), compartilhada por todos os dispositivos dela.
    CREATE TABLE identities (
        name TEXT PRIMARY KEY,
        identity_key BLOB NOT NULL
    ) STRICT;

    CREATE TABLE sessions (
        name TEXT NOT NULL,
        device_id INTEGER NOT NULL,
        record BLOB NOT NULL,
        PRIMARY KEY (name, device_id)
    ) STRICT;

    CREATE TABLE pre_keys (
        id INTEGER PRIMARY KEY,
        record BLOB NOT NULL
    ) STRICT;

    CREATE TABLE signed_pre_keys (
        id INTEGER PRIMARY KEY,
        record BLOB NOT NULL
    ) STRICT;

    CREATE TABLE kyber_pre_keys (
        id INTEGER PRIMARY KEY,
        record BLOB NOT NULL,
        last_resort INTEGER NOT NULL CHECK (last_resort IN (0, 1))
    ) STRICT;

    -- Base keys já usadas com cada pré-chave Kyber de último recurso, para recusar replay.
    CREATE TABLE kyber_base_keys_seen (
        kyber_pre_key_id INTEGER NOT NULL REFERENCES kyber_pre_keys (id) ON DELETE CASCADE,
        signed_pre_key_id INTEGER NOT NULL,
        base_key BLOB NOT NULL,
        PRIMARY KEY (kyber_pre_key_id, signed_pre_key_id, base_key)
    ) STRICT;

    CREATE TABLE sender_keys (
        name TEXT NOT NULL,
        device_id INTEGER NOT NULL,
        distribution_id BLOB NOT NULL,
        record BLOB NOT NULL,
        PRIMARY KEY (name, device_id, distribution_id)
    ) STRICT;
    ",
    // 2: endereço do próprio dispositivo, atribuído pelo servidor depois do registro.
    "
    CREATE TABLE local_address (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        aci TEXT NOT NULL,
        device_id INTEGER NOT NULL
    ) STRICT;
    ",
    // 3: profile key de cada contato (por conta), da qual sai a unidentified access key do
    // sealed sender. Segredo: só sai do banco para derivar a chave.
    "
    CREATE TABLE peer_profile_keys (
        aci TEXT PRIMARY KEY,
        profile_key BLOB NOT NULL CHECK (length(profile_key) = 32)
    ) STRICT;
    ",
    // 4: mensagens recebidas, gravadas na mesma transação que avança o ratchet. AUTOINCREMENT:
    // o id é o cursor do app e nunca volta a ser usado depois de apagar a última mensagem.
    "
    CREATE TABLE received_messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_aci TEXT NOT NULL,
        sender_device_id INTEGER NOT NULL,
        server_timestamp INTEGER NOT NULL,
        body BLOB NOT NULL
    ) STRICT;
    ",
    // 5: idempotência por `client_message_id` (falaai-proto `Envelope`) e outbox.
    //
    // Quem envia reenvia com o mesmo id quando não viu o `SendAck`; o índice único deixa o
    // receptor reconhecer a cópia. Mensagens anteriores ficam sem id (NULL não colide).
    //
    // `outbox`: mensagens a enviar, na ordem de `id`. `outcome` é NULL enquanto pendente; com
    // resultado (0 aceita, maior que 0 recusada de vez) o corpo é apagado e a linha espera só
    // o evento chegar ao app.
    "
    ALTER TABLE received_messages ADD COLUMN client_message_id BLOB;
    CREATE UNIQUE INDEX received_messages_client_message_id
        ON received_messages (sender_aci, sender_device_id, client_message_id);

    CREATE TABLE outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_message_id BLOB NOT NULL UNIQUE CHECK (length(client_message_id) = 16),
        recipient_aci TEXT NOT NULL,
        recipient_device_id INTEGER NOT NULL,
        body BLOB NOT NULL,
        outcome INTEGER
    ) STRICT;
    ",
];
