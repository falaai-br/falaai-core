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
    // 6: safety numbers. A chave de identidade que o usuário verificou para cada contato
    // (por conta, como `identities`): se a atual for outra, a conversa está com a identidade
    // mudada e o envio fica bloqueado. E a marca, em cada mensagem recebida, de que a identidade
    // do remetente mudou ao decifrá-la, para o aviso aparecer no lugar certo da conversa,
    // inclusive quando quem decifrou foi a extensão de notificação.
    "
    CREATE TABLE verified_identities (
        name TEXT PRIMARY KEY,
        identity_key BLOB NOT NULL
    ) STRICT;

    ALTER TABLE received_messages
        ADD COLUMN identity_changed INTEGER NOT NULL DEFAULT 0
        CHECK (identity_changed IN (0, 1));
    ",
    // 7: mensagens de protocolo (recibos e digitação) e a opção de recibo de leitura.
    //
    // `outbox.kind`: 0 texto (o corpo é o texto, como antes), 1 recibo (o corpo é o conteúdo
    // E2EE já serializado). Digitação nunca entra na outbox nem em tabela nenhuma.
    //
    // `received_receipts`: recibos recebidos, gravados na transação que avança o ratchet, como
    // as mensagens; `message_ids` são os `client_message_id` (16 bytes cada, concatenados) das
    // mensagens deste aparelho que o remetente confirma. Deduplicados pelo `client_message_id`
    // do envelope, como as mensagens.
    //
    // `settings`: uma linha; sem ela, valem os padrões (recibo de leitura ligado).
    "
    ALTER TABLE outbox ADD COLUMN kind INTEGER NOT NULL DEFAULT 0 CHECK (kind IN (0, 1));

    CREATE TABLE received_receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_aci TEXT NOT NULL,
        sender_device_id INTEGER NOT NULL,
        client_message_id BLOB,
        kind INTEGER NOT NULL CHECK (kind IN (1, 2)),
        message_ids BLOB NOT NULL CHECK (length(message_ids) > 0 AND length(message_ids) % 16 = 0),
        server_timestamp INTEGER NOT NULL
    ) STRICT;
    CREATE UNIQUE INDEX received_receipts_client_message_id
        ON received_receipts (sender_aci, sender_device_id, client_message_id);

    CREATE TABLE settings (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        read_receipts INTEGER NOT NULL CHECK (read_receipts IN (0, 1))
    ) STRICT;
    ",
];
