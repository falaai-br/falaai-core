//! Banco local cifrado: SQLCipher via rusqlite.
//!
//! A chave de 256 bits vem da plataforma (Keychain no iOS, Keystore no Android) e é aplicada
//! como chave bruta, sem derivação por senha. O banco abre em WAL com busy timeout porque o
//! app e a Notification Service Extension do iOS abrem o mesmo arquivo.
//!
//! Operações que avançam o ratchet rodam numa transação explícita ([`Database::begin`]) que
//! segura também um lock de arquivo ao lado do banco: nunca dois processos avançam o mesmo
//! ratchet, e uma falha no meio não deixa o estado pela metade.

mod schema;

use std::ffi::OsString;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use rusqlite::{Connection, ErrorCode, TransactionBehavior};
use zeroize::Zeroizing;

/// Quanto uma conexão espera por um lock de outro processo antes de desistir. Cabe folgado nos
/// ~30s que o iOS dá à Notification Service Extension.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Intervalo entre tentativas de pegar o lock de arquivo, que não tem espera com timeout.
const LOCK_RETRY: Duration = Duration::from_millis(5);

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
    /// Falha ao abrir ou travar o arquivo de lock.
    #[error("falha no arquivo de lock")]
    LockFile,
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
    state: Mutex<State>,
    /// Avisado quando a transação em curso termina.
    idle: Condvar,
    /// Lock de arquivo ao lado do banco, exclusivo entre processos. `None` no banco em memória.
    lock_file: Option<File>,
    /// Espera máxima por outro processo, no lock de arquivo e no SQLite.
    timeout: Duration,
}

struct State {
    conn: Connection,
    /// Thread dona da transação aberta por [`Database::begin`]. As outras esperam ela terminar.
    owner: Option<ThreadId>,
    /// `PRAGMA data_version` da última consulta de [`Database::changed_elsewhere`].
    data_version: i64,
}

impl Database {
    /// Abre (ou cria) o banco em `path` com `key`, ativa WAL e aplica as migrações pendentes.
    /// O lock de arquivo fica em `path` com o sufixo `-lock`.
    pub(crate) fn open(path: &Path, key: &DatabaseKey) -> Result<Self, StorageError> {
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(lock_path(path))
            .map_err(|_| StorageError::LockFile)?;
        Self::setup(Connection::open(path)?, key, Some(lock_file))
    }

    /// Banco em memória, para testes.
    #[cfg(test)]
    pub(crate) fn open_in_memory(key: &DatabaseKey) -> Result<Self, StorageError> {
        Self::setup(Connection::open_in_memory()?, key, None)
    }

    fn setup(
        mut conn: Connection,
        key: &DatabaseKey,
        lock_file: Option<File>,
    ) -> Result<Self, StorageError> {
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
        let data_version = data_version(&conn)?;
        Ok(Self {
            state: Mutex::new(State {
                conn,
                owner: None,
                data_version,
            }),
            idle: Condvar::new(),
            lock_file,
            timeout: BUSY_TIMEOUT,
        })
    }

    /// Encurta a espera por outro processo, para os testes de contenção não levarem segundos.
    #[cfg(test)]
    pub(crate) fn set_timeout(&mut self, timeout: Duration) -> Result<(), StorageError> {
        self.timeout = timeout;
        self.with(|c| c.busy_timeout(timeout))
    }

    /// Executa `f` com a conexão. `f` deve só tocar o banco: tudo nele roda sob o mutex. Com
    /// uma transação aberta por outra thread, espera ela terminar; na thread dona, `f` roda
    /// dentro da transação.
    pub(crate) fn with<T>(
        &self,
        f: impl FnOnce(&mut Connection) -> rusqlite::Result<T>,
    ) -> Result<T, StorageError> {
        let mut state = self.turn();
        Ok(f(&mut state.conn)?)
    }

    /// Abre uma transação `IMMEDIATE` na thread atual e segura o lock de arquivo até
    /// [`Self::commit`] ou [`Self::rollback`], que têm de ser chamados na mesma thread. Outro
    /// processo segurando o lock além do timeout dá [`StorageError::Busy`].
    ///
    /// O lock fica preso só durante a operação: o iOS encerra um processo suspenso com lock
    /// de arquivo no App Group.
    pub(crate) fn begin(&self) -> Result<(), StorageError> {
        let me = thread::current().id();
        {
            let mut state = self.turn();
            if state.owner.is_some() {
                // Transação aninhada: erro de quem chama, não do banco.
                return Err(StorageError::Sqlite);
            }
            // Reserva a vez antes de esperar pelo lock de arquivo: as outras threads esperam em
            // `turn` até a transação terminar.
            state.owner = Some(me);
        }
        let begun = self.lock_ratchet().and_then(|()| {
            let result = lock(&self.state).conn.execute_batch("BEGIN IMMEDIATE");
            result.map_err(|error| {
                self.unlock_ratchet();
                StorageError::from(error)
            })
        });
        if begun.is_err() {
            self.release(lock(&self.state));
        }
        begun
    }

    /// Confirma a transação de [`Self::begin`]. Se o `COMMIT` falha, a transação é desfeita.
    pub(crate) fn commit(&self) -> Result<(), StorageError> {
        self.finish("COMMIT")
    }

    /// Desfaz a transação de [`Self::begin`].
    pub(crate) fn rollback(&self) -> Result<(), StorageError> {
        self.finish("ROLLBACK")
    }

    /// `true` se outra conexão (na prática, outro processo: o app ou a extensão de notificação)
    /// gravou no banco desde a última chamada ou, na primeira, desde a abertura.
    pub(crate) fn changed_elsewhere(&self) -> Result<bool, StorageError> {
        let mut state = self.turn();
        let current = data_version(&state.conn)?;
        let changed = current != state.data_version;
        state.data_version = current;
        Ok(changed)
    }

    fn finish(&self, sql: &str) -> Result<(), StorageError> {
        let state = lock(&self.state);
        if state.owner != Some(thread::current().id()) {
            return Err(StorageError::Sqlite);
        }
        let result = state.conn.execute_batch(sql);
        if !state.conn.is_autocommit() {
            // O COMMIT falhou e deixou a transação aberta. O ROLLBACK só falha sem transação.
            let _ = state.conn.execute_batch("ROLLBACK");
        }
        self.unlock_ratchet();
        self.release(state);
        Ok(result?)
    }

    /// Mutex da conexão, depois de esperar o fim de uma transação de outra thread.
    fn turn(&self) -> MutexGuard<'_, State> {
        let me = thread::current().id();
        self.idle
            .wait_while(lock(&self.state), |state| {
                state.owner.is_some_and(|owner| owner != me)
            })
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn release(&self, mut state: MutexGuard<'_, State>) {
        state.owner = None;
        drop(state);
        self.idle.notify_all();
    }

    fn lock_ratchet(&self) -> Result<(), StorageError> {
        let Some(file) = &self.lock_file else {
            return Ok(());
        };
        let deadline = Instant::now() + self.timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(()),
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(LOCK_RETRY);
                }
                Err(TryLockError::WouldBlock) => return Err(StorageError::Busy),
                Err(TryLockError::Error(_)) => return Err(StorageError::LockFile),
            }
        }
    }

    fn unlock_ratchet(&self) {
        if let Some(file) = &self.lock_file {
            // Só falha se o lock não está preso; fechar o arquivo também o solta.
            let _ = file.unlock();
        }
    }
}

/// Os mutexes só protegem estado que segue consistente após um panic: uma transação aberta é
/// desfeita no drop da conexão.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn lock_path(path: &Path) -> PathBuf {
    let mut name = OsString::from(path.as_os_str());
    name.push("-lock");
    PathBuf::from(name)
}

fn data_version(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("PRAGMA data_version", [], |row| row.get(0))
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
    if pending.is_empty() {
        // Sem gravar: o outro processo veria a abertura como mudança (`changed_elsewhere`).
        return Ok(());
    }
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

    fn count_pre_keys(db: &Database) -> Result<i64, StorageError> {
        db.with(|c| c.query_row("SELECT count(*) FROM pre_keys", [], |r| r.get(0)))
    }

    fn insert_pre_key(db: &Database, id: u32) -> Result<usize, StorageError> {
        db.with(|c| c.execute("INSERT INTO pre_keys (id, record) VALUES (?1, x'01')", [id]))
    }

    #[test]
    fn transacao_grava_tudo_no_commit_e_nada_no_rollback() -> TestResult {
        let dir = tempfile::tempdir()?;
        let db = Database::open(&dir.path().join("falaai.db"), &key(1)?)?;
        db.begin()?;
        insert_pre_key(&db, 1)?;
        insert_pre_key(&db, 2)?;
        db.rollback()?;
        assert_eq!(count_pre_keys(&db)?, 0);

        db.begin()?;
        insert_pre_key(&db, 1)?;
        db.commit()?;
        assert_eq!(count_pre_keys(&db)?, 1);
        Ok(())
    }

    #[test]
    fn commit_que_falha_desfaz_a_transacao() -> TestResult {
        let db = Database::open_in_memory(&key(1)?)?;
        db.with(|c| {
            c.execute_batch(
                "CREATE TABLE parent (id INTEGER PRIMARY KEY);
                 CREATE TABLE child (parent INTEGER REFERENCES parent (id)
                     DEFERRABLE INITIALLY DEFERRED);",
            )
        })?;
        db.begin()?;
        insert_pre_key(&db, 1)?;
        // A chave estrangeira adiada só é checada no COMMIT.
        db.with(|c| c.execute("INSERT INTO child (parent) VALUES (7)", []))?;
        assert_eq!(db.commit(), Err(StorageError::Sqlite));
        assert_eq!(count_pre_keys(&db)?, 0);
        db.begin()?;
        db.commit()?;
        Ok(())
    }

    #[test]
    fn transacao_aninhada_ou_sem_begin_e_recusada() -> TestResult {
        let db = Database::open_in_memory(&key(1)?)?;
        assert_eq!(db.commit(), Err(StorageError::Sqlite));
        assert_eq!(db.rollback(), Err(StorageError::Sqlite));
        db.begin()?;
        assert_eq!(db.begin(), Err(StorageError::Sqlite));
        db.commit()?;
        Ok(())
    }

    #[test]
    fn lock_de_arquivo_fica_ao_lado_do_banco() -> TestResult {
        let dir = tempfile::tempdir()?;
        let _db = Database::open(&dir.path().join("falaai.db"), &key(1)?)?;
        assert!(dir.path().join("falaai.db-lock").is_file());
        Ok(())
    }

    #[test]
    fn outro_processo_nao_abre_transacao_enquanto_o_lock_esta_preso() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let app = Database::open(&path, &key(1)?)?;
        let mut extension = Database::open(&path, &key(1)?)?;
        extension.set_timeout(Duration::from_millis(50))?;

        app.begin()?;
        let started = Instant::now();
        assert_eq!(extension.begin(), Err(StorageError::Busy));
        assert!(started.elapsed() >= Duration::from_millis(50));
        // WAL: a extensão ainda lê o que já foi confirmado.
        assert_eq!(count_pre_keys(&extension)?, 0);
        app.commit()?;

        extension.begin()?;
        insert_pre_key(&extension, 1)?;
        extension.commit()?;
        assert_eq!(count_pre_keys(&app)?, 1);
        Ok(())
    }

    #[test]
    fn outro_processo_espera_o_fim_da_transacao() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let app = Database::open(&path, &key(1)?)?;
        let extension = Database::open(&path, &key(1)?)?;

        app.begin()?;
        let waiting = thread::spawn(move || -> Result<i64, StorageError> {
            extension.begin()?;
            // Só entra depois do commit do app, e vê o que ele gravou.
            let count = count_pre_keys(&extension)?;
            extension.commit()?;
            Ok(count)
        });
        thread::sleep(Duration::from_millis(100));
        insert_pre_key(&app, 1)?;
        app.commit()?;
        assert_eq!(waiting.join().map_err(|_| "panic")??, 1);
        Ok(())
    }

    #[test]
    fn outra_thread_espera_a_transacao_em_vez_de_entrar_nela() -> TestResult {
        let db = std::sync::Arc::new(Database::open_in_memory(&key(1)?)?);
        db.begin()?;
        insert_pre_key(&db, 1)?;
        let reader = {
            let db = db.clone();
            thread::spawn(move || count_pre_keys(&db))
        };
        thread::sleep(Duration::from_millis(100));
        db.rollback()?;
        // Dentro da transação veria a pré-chave ainda não confirmada.
        assert_eq!(reader.join().map_err(|_| "panic")??, 0);
        Ok(())
    }

    #[test]
    fn mudanca_feita_por_outro_processo_e_sinalizada() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("falaai.db");
        let app = Database::open(&path, &key(1)?)?;
        let extension = Database::open(&path, &key(1)?)?;
        assert!(!app.changed_elsewhere()?);

        insert_pre_key(&app, 1)?;
        assert!(!app.changed_elsewhere()?, "gravação própria");

        extension.begin()?;
        insert_pre_key(&extension, 2)?;
        extension.commit()?;
        assert!(app.changed_elsewhere()?);
        assert!(!app.changed_elsewhere()?, "já sinalizada");
        assert!(extension.changed_elsewhere()?, "o app gravou antes");
        Ok(())
    }
}
