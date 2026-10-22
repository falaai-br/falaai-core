//! Banco local cifrado: SQLCipher via rusqlite.
//!
//! A chave de 256 bits vem da plataforma (Keychain no iOS, Keystore no Android) e é aplicada
//! como chave bruta, sem derivação por senha. O banco abre em WAL com busy timeout porque o
//! app e a Notification Service Extension do iOS abrem o mesmo arquivo.

mod schema;

use std::fmt;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, TransactionBehavior};
use zeroize::Zeroizing;

/// Quanto uma conexão espera por um lock de outro processo antes de desistir. Cabe folgado nos
/// ~30s que o iOS dá à Notification Service Extension.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Erro do armazenamento local. As variantes não carregam SQL, caminho nem dados.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum StorageError {
    /// A chave recebida da plataforma não tem 32 bytes.
    #[error("chave do banco com tamanho inválido")]
    InvalidKeyLength,
    /// O arquivo não abre com a chave dada: chave errada ou arquivo corrompido.
    #[error("chave do banco incorreta ou arquivo corrompido")]
    WrongKeyOrCorrupt,
    /// Outro processo segurou o lock além do busy timeout.
    #[error("banco ocupado por outro processo")]
    Busy,
    /// O banco foi migrado por uma versão mais nova do app.
    #[error("banco de versão mais nova que o app")]
    UnsupportedVersion,
    /// Qualquer outra falha do SQLite.
    #[error("falha no banco local")]
    Sqlite,
}

impl From<rusqlite::Error> for StorageError {
    fn from(error: rusqlite::Error) -> Self {
        match error.sqlite_error_code() {
            Some(ErrorCode::NotADatabase) => Self::WrongKeyOrCorrupt,
            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => Self::Busy,
            _ => Self::Sqlite,
        }
    }
}

/// Chave de 256 bits do banco; zerada da memória ao sair de escopo.
pub(crate) struct DatabaseKey(Zeroizing<[u8; 32]>);

impl DatabaseKey {
    /// Copia a chave entregue pela plataforma. Exige exatamente 32 bytes.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, StorageError> {
        let mut key = Zeroizing::new([0; 32]);
        if bytes.len() != key.len() {
            return Err(StorageError::InvalidKeyLength);
        }
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// `PRAGMA key` com a chave bruta em hexadecimal (`x'…'`), que dispensa o PBKDF2 do
    /// SQLCipher. A string é alocada uma vez no tamanho exato e zerada ao sair de escopo.
    fn pragma(&self) -> Zeroizing<String> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        const PREFIX: &str = "PRAGMA key = \"x'";
        const SUFFIX: &str = "'\";";
        let mut sql = Zeroizing::new(String::with_capacity(
            PREFIX.len() + 2 * self.0.len() + SUFFIX.len(),
        ));
        sql.push_str(PREFIX);
        for byte in self.0.iter() {
            sql.push(char::from(HEX[usize::from(byte >> 4)]));
            sql.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        sql.push_str(SUFFIX);
        sql
    }
}

impl fmt::Debug for DatabaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DatabaseKey(<omitida>)")
    }
}

/// Banco local aberto e migrado. Uma conexão por processo, serializada por mutex.
pub(crate) struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Abre (ou cria) o banco em `path` com `key`, ativa WAL e aplica as migrações pendentes.
    pub(crate) fn open(path: &Path, key: &DatabaseKey) -> Result<Self, StorageError> {
        Self::setup(Connection::open(path)?, key)
    }

    /// Banco em memória, para testes.
    #[cfg(test)]
    pub(crate) fn open_in_memory(key: &DatabaseKey) -> Result<Self, StorageError> {
        Self::setup(Connection::open_in_memory()?, key)
    }

    fn setup(mut conn: Connection, key: &DatabaseKey) -> Result<Self, StorageError> {
        conn.execute_batch(&key.pragma())?;
        conn.busy_timeout(BUSY_TIMEOUT)?;
        // Primeira leitura: com a chave errada falha aqui, com SQLITE_NOTADB.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })?;
        // WAL deixa a extensão ler enquanto o app escreve; fica gravado no arquivo.
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON;")?;
        migrate(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Executa `f` com a conexão. `f` deve só tocar o banco: tudo nele roda sob o mutex.
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StorageError> {
        // Um panic com o lock na mão não deixa a conexão inconsistente: uma transação aberta
        // é desfeita no drop.
        let mut conn = self.conn.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(f(&mut conn)?)
    }
}

/// Aplica as migrações pendentes numa transação `IMMEDIATE`, que pega o lock de escrita antes
/// de ler a versão: dois processos abrindo juntos não migram em dobro.
fn migrate(conn: &mut Connection) -> Result<(), StorageError> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: u32 = tx.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let pending = usize::try_from(version)
        .ok()
        .and_then(|version| schema::MIGRATIONS.get(version..))
        .ok_or(StorageError::UnsupportedVersion)?;
    for migration in pending {
        tx.execute_batch(migration)?;
    }
    tx.pragma_update(None, "user_version", schema::VERSION)?;
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn key(byte: u8) -> Result<DatabaseKey, StorageError> {
        DatabaseKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn chave_exige_32_bytes() {
        for len in [0, 16, 31, 33, 64] {
            assert_eq!(
                DatabaseKey::from_bytes(&vec![7; len]).err(),
                Some(StorageError::InvalidKeyLength),
                "{len}"
            );
        }
    }

    #[test]
    fn debug_da_chave_omite_os_bytes() -> TestResult {
        assert_eq!(format!("{:?}", key(0xAB)?), "DatabaseKey(<omitida>)");
        Ok(())
    }

    #[test]
    fn pragma_usa_chave_bruta_em_hexadecimal() -> TestResult {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0f;
        bytes[31] = 0xa0;
        let pragma = DatabaseKey::from_bytes(&bytes)?.pragma();
        let expected = format!("PRAGMA key = \"x'0f{}a0'\";", "00".repeat(30));
        assert_eq!(pragma.as_str(), expected);
        assert_eq!(pragma.capacity(), pragma.len(), "sem realocação");
        Ok(())
    }

    #[test]
    fn sqlcipher_esta_linkado() -> TestResult {
        let db = Database::open_in_memory(&key(1)?)?;
        let version: String =
            db.with(|c| c.query_row("PRAGMA cipher_version", [], |r| r.get(0)))?;
        assert!(!version.is_empty());
        Ok(())
    }

    #[test]
    fn arquivo_fica_cifrado_em_disco() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let marker = b"marcador-em-claro-0123456789";
        {
            let db = Database::open(&path, &key(1)?)?;
            db.with(|c| {
                c.execute(
                    "INSERT INTO pre_keys (id, record) VALUES (1, ?1)",
                    [&marker[..]],
                )
            })?;
        }
        let bytes = fs::read(&path)?;
        assert!(!bytes.is_empty());
        assert!(
            !bytes.starts_with(b"SQLite format 3\0"),
            "cabeçalho em claro"
        );
        assert!(
            !bytes.windows(marker.len()).any(|w| w == marker),
            "conteúdo em claro"
        );
        Ok(())
    }

    #[test]
    fn chave_errada_e_recusada() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        drop(Database::open(&path, &key(1)?)?);
        assert_eq!(
            Database::open(&path, &key(2)?).err(),
            Some(StorageError::WrongKeyOrCorrupt)
        );
        Ok(())
    }

    #[test]
    fn abre_em_wal_com_busy_timeout() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("falaai.db"), &key(1)?)?;
        let (journal, timeout, foreign_keys, secure_delete) = db.with(|c| {
            Ok((
                c.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))?,
                c.query_row("PRAGMA busy_timeout", [], |r| r.get::<_, u32>(0))?,
                c.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, bool>(0))?,
                c.query_row("PRAGMA secure_delete", [], |r| r.get::<_, i64>(0))?,
            ))
        })?;
        assert_eq!(journal, "wal");
        assert_eq!(u128::from(timeout), BUSY_TIMEOUT.as_millis());
        assert!(foreign_keys);
        assert_eq!(secure_delete, 1);
        Ok(())
    }

    #[test]
    fn duas_conexoes_compartilham_o_arquivo() -> TestResult {
        // Simula app e Notification Service Extension abrindo o mesmo banco.
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let app = Database::open(&path, &key(1)?)?;
        let extension = Database::open(&path, &key(1)?)?;
        app.with(|c| c.execute("INSERT INTO pre_keys (id, record) VALUES (1, x'01')", []))?;
        let count: i64 =
            extension.with(|c| c.query_row("SELECT count(*) FROM pre_keys", [], |r| r.get(0)))?;
        assert_eq!(count, 1);
        Ok(())
    }

    #[test]
    fn migracoes_sao_idempotentes_e_persistem() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        drop(Database::open(&path, &key(1)?)?);
        let db = Database::open(&path, &key(1)?)?;
        let version: u32 = db.with(|c| c.query_row("PRAGMA user_version", [], |r| r.get(0)))?;
        assert_eq!(version, schema::VERSION);
        Ok(())
    }

    #[test]
    fn banco_de_versao_mais_nova_e_recusado() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let db = Database::open(&path, &key(1)?)?;
        db.with(|c| c.pragma_update(None, "user_version", schema::VERSION + 1))?;
        drop(db);
        assert_eq!(
            Database::open(&path, &key(1)?).err(),
            Some(StorageError::UnsupportedVersion)
        );
        Ok(())
    }
}
