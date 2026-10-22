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
];
