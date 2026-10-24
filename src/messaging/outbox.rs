//! Outbox: mensagens à espera de envio, no banco local, e o [`Courier`] que as envia.
//!
//! [`Outbox::push`] grava a mensagem com um `client_message_id` novo; o [`Courier`], uma thread
//! que roda enquanto o núcleo está conectado, envia na ordem de gravação. Cada tentativa cifra de
//! novo, porque o certificado de remetente dentro do selo vence em 24h e um envelope guardado
//! deixaria de abrir. O `client_message_id` é o mesmo em todas: se uma tentativa chegou ao
//! servidor e o `SendAck` se perdeu, o receptor descarta a cópia (ver [`super::Inbox::record`]).
//!
//! Falha passageira (rede, limite de taxa, sem certificado de remetente) para a fila, que tenta
//! de novo com backoff exponencial; reconexão, certificado novo e assinante novo acordam o
//! [`Courier`] na hora e zeram o backoff. Recusa definitiva (destinatário inexistente, sem
//! sessão) não volta para a fila. Aceita ou recusada, a mensagem só sai do banco depois que o
//! evento chega ao app; sem assinante, o evento vai quando houver um.

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::types::Type;
use rusqlite::{OptionalExtension, params};

use super::corrupt;
use crate::protocol::{Address, Plaintext};
use crate::storage::{Database, StorageError};

/// Tamanho do `client_message_id`: um UUID.
pub(crate) const CLIENT_MESSAGE_ID_LEN: usize = 16;

/// Id que o remetente dá a uma mensagem, o mesmo em todo reenvio.
pub(crate) type ClientMessageId = [u8; CLIENT_MESSAGE_ID_LEN];

/// Espera entre tentativas: começa em `min` e dobra a cada falha seguida, até `max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Backoff {
    pub(crate) min: Duration,
    pub(crate) max: Duration,
}

/// Backoff do app.
pub(crate) const BACKOFF: Backoff = Backoff {
    min: Duration::from_secs(1),
    max: Duration::from_secs(5 * 60),
};

/// Mensagem na fila. Sem `Debug`: o texto claro não pode ir para log.
pub(crate) struct Pending {
    id: i64,
    pub(crate) client_message_id: ClientMessageId,
    pub(crate) to: Address,
    pub(crate) body: Plaintext,
}

/// Resultado final de uma mensagem da fila.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// O servidor gravou na fila do destinatário.
    Sent,
    /// Recusada de vez: reenviar igual não adianta.
    Rejected(Rejection),
}

/// Por que uma mensagem foi recusada de vez.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// O servidor recusou o envelope.
    InvalidEnvelope,
    /// Destinatário ou dispositivo inexistente.
    UnknownDestination,
    /// Não há sessão com o destinatário.
    SessionNotFound,
    /// A identidade do destinatário mudou e não foi aceita.
    UntrustedIdentity,
}

impl Outcome {
    /// Código gravado em `outbox.outcome`. Publicado, um código nunca muda de sentido.
    fn code(self) -> i64 {
        match self {
            Self::Sent => 0,
            Self::Rejected(Rejection::InvalidEnvelope) => 1,
            Self::Rejected(Rejection::UnknownDestination) => 2,
            Self::Rejected(Rejection::SessionNotFound) => 3,
            Self::Rejected(Rejection::UntrustedIdentity) => 4,
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::Sent,
            1 => Self::Rejected(Rejection::InvalidEnvelope),
            2 => Self::Rejected(Rejection::UnknownDestination),
            3 => Self::Rejected(Rejection::SessionNotFound),
            4 => Self::Rejected(Rejection::UntrustedIdentity),
            _ => return None,
        })
    }
}

/// Mensagem com resultado, à espera de o evento chegar ao app.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Settled {
    id: i64,
    pub(crate) client_message_id: ClientMessageId,
    pub(crate) outcome: Outcome,
}

/// Fila de envio, sobre o banco local. Clonar só copia o handle da conexão.
#[derive(Clone)]
pub(crate) struct Outbox {
    db: Arc<Database>,
}

impl Outbox {
    /// Fila sobre `db`.
    pub(crate) fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Põe `body` na fila para `to`, com um `client_message_id` novo (UUID v4), e devolve o id.
    pub(crate) fn push(&self, to: &Address, body: &[u8]) -> Result<ClientMessageId, StorageError> {
        let client_message_id = uuid::Builder::from_random_bytes(rand::random())
            .into_uuid()
            .into_bytes();
        self.db.with(|c| {
            c.execute(
                "INSERT INTO outbox (client_message_id, recipient_aci, recipient_device_id, body)
                 VALUES (?1, ?2, ?3, ?4)",
                params![client_message_id, to.aci(), to.device_id(), body],
            )
        })?;
        Ok(client_message_id)
    }

    /// A mensagem mais antiga ainda sem resultado.
    pub(crate) fn next(&self) -> Result<Option<Pending>, StorageError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT id, client_message_id, recipient_aci, recipient_device_id, body
                 FROM outbox WHERE outcome IS NULL ORDER BY id LIMIT 1",
                [],
                |row| {
                    let aci: String = row.get(2)?;
                    Ok(Pending {
                        id: row.get(0)?,
                        client_message_id: row.get(1)?,
                        to: Address::new(&aci, row.get(3)?).map_err(|_| corrupt(2, Type::Text))?,
                        body: Plaintext::new(row.get(4)?),
                    })
                },
            )
            .optional()
        })
    }

    /// Grava o resultado da mensagem `id` e apaga o corpo dela.
    fn settle(&self, id: i64, outcome: Outcome) -> Result<(), StorageError> {
        self.db.with(|c| {
            c.execute(
                "UPDATE outbox SET outcome = ?2, body = x'' WHERE id = ?1",
                params![id, outcome.code()],
            )
        })?;
        Ok(())
    }

    /// Mensagens com resultado cujo evento ainda não chegou ao app, na ordem da fila.
    pub(crate) fn settled(&self) -> Result<Vec<Settled>, StorageError> {
        self.db.with(|c| {
            let mut select = c.prepare_cached(
                "SELECT id, client_message_id, outcome FROM outbox
                 WHERE outcome IS NOT NULL ORDER BY id",
            )?;
            let rows = select.query_map([], |row| {
                Ok(Settled {
                    id: row.get(0)?,
                    client_message_id: row.get(1)?,
                    outcome: Outcome::from_code(row.get(2)?)
                        .ok_or_else(|| corrupt(2, Type::Integer))?,
                })
            })?;
            rows.collect()
        })
    }

    /// Tira a mensagem `id` do banco.
    fn remove(&self, id: i64) -> Result<(), StorageError> {
        self.db
            .with(|c| c.execute("DELETE FROM outbox WHERE id = ?1", [id]))?;
        Ok(())
    }
}

enum Signal {
    /// Mensagem nova na fila.
    Pushed,
    /// Algo que destrava a fila mudou: conexão nova, certificado novo, assinante novo.
    Retry,
    Stop,
}

/// Acorda o [`Courier`]. Clonar só copia o canal; sem o [`Courier`], não faz nada.
#[derive(Clone)]
pub(crate) struct Wake(Sender<Signal>);

impl Wake {
    /// Há mensagem nova na fila. Durante o backoff não antecipa a tentativa: a fila está parada
    /// pela mensagem da frente.
    pub(crate) fn pushed(&self) {
        let _ = self.0.send(Signal::Pushed);
    }

    /// Tenta já e zera o backoff.
    pub(crate) fn retry(&self) {
        let _ = self.0.send(Signal::Retry);
    }
}

/// Lado do [`Courier`] do canal de [`Wake`].
pub(crate) struct Signals(Receiver<Signal>);

/// Canal para acordar o [`Courier`], criado antes dele: quem acorda (o transporte, na
/// reconexão) pode nascer antes.
pub(crate) fn channel() -> (Wake, Signals) {
    let (sender, receiver) = mpsc::channel();
    (Wake(sender), Signals(receiver))
}

/// Resultado de uma tentativa de envio.
pub(crate) enum Attempt {
    /// Acabou: a mensagem sai da fila.
    Done(Outcome),
    /// Falha passageira: a fila para e tenta de novo depois do backoff.
    Retry,
}

/// Tenta enviar uma mensagem da fila.
pub(crate) type AttemptFn = Box<dyn FnMut(&Pending) -> Attempt + Send>;

/// Entrega ao app o resultado de uma mensagem; `false` se não há quem ouça.
pub(crate) type NotifyFn = Box<dyn FnMut(&ClientMessageId, Outcome) -> bool + Send>;

/// Thread que esvazia a outbox. Ao sair de escopo, ela termina depois da tentativa em curso.
pub(crate) struct Courier {
    wake: Wake,
}

impl Courier {
    /// Sobe a thread, que esvazia `outbox` com `attempt` e entrega cada resultado com `notify`,
    /// e volta a esvaziar a cada sinal de `signals`. `wake` é o outro lado de `signals`.
    pub(crate) fn start(
        outbox: Outbox,
        (wake, signals): (Wake, Signals),
        backoff: Backoff,
        attempt: AttemptFn,
        notify: NotifyFn,
    ) -> io::Result<Self> {
        let dispatch = Dispatch {
            outbox,
            signals: signals.0,
            backoff,
            attempt,
            notify,
        };
        thread::Builder::new()
            .name("falaai-outbox".to_owned())
            .spawn(move || dispatch.run())?;
        Ok(Self { wake })
    }

    /// Acorda a thread.
    pub(crate) fn wake(&self) -> &Wake {
        &self.wake
    }
}

impl Drop for Courier {
    fn drop(&mut self) {
        let _ = self.wake.0.send(Signal::Stop);
    }
}

/// Como terminou uma passada pela fila.
#[derive(PartialEq, Eq)]
enum Backlog {
    /// Fila vazia.
    Empty,
    /// Ficou mensagem para tentar de novo.
    Stuck,
}

/// Por que a espera terminou.
enum Wakeup {
    /// Esvaziar a fila de novo.
    Flush,
    /// Esvaziar a fila de novo, com o backoff zerado.
    Reset,
    /// O backoff passou.
    Elapsed,
    Stop,
}

struct Dispatch {
    outbox: Outbox,
    signals: Receiver<Signal>,
    backoff: Backoff,
    attempt: AttemptFn,
    notify: NotifyFn,
}

impl Dispatch {
    fn run(mut self) {
        let mut delay = self.backoff.min;
        loop {
            let retry_at = match self.flush() {
                Backlog::Empty => {
                    delay = self.backoff.min;
                    None
                }
                Backlog::Stuck => Some(Instant::now() + delay),
            };
            match self.wait(retry_at) {
                Wakeup::Flush => {}
                Wakeup::Reset => delay = self.backoff.min,
                Wakeup::Elapsed => delay = (delay * 2).min(self.backoff.max),
                Wakeup::Stop => return,
            }
        }
    }

    /// Espera um sinal ou, com `retry_at`, no máximo até lá.
    fn wait(&self, retry_at: Option<Instant>) -> Wakeup {
        let Some(retry_at) = retry_at else {
            return match self.signals.recv() {
                Ok(Signal::Pushed) => Wakeup::Flush,
                Ok(Signal::Retry) => Wakeup::Reset,
                Ok(Signal::Stop) | Err(_) => Wakeup::Stop,
            };
        };
        loop {
            let left = retry_at.saturating_duration_since(Instant::now());
            match self.signals.recv_timeout(left) {
                Ok(Signal::Pushed) => {}
                Ok(Signal::Retry) => return Wakeup::Reset,
                Err(RecvTimeoutError::Timeout) => return Wakeup::Elapsed,
                Ok(Signal::Stop) | Err(RecvTimeoutError::Disconnected) => return Wakeup::Stop,
            }
        }
    }

    /// Entrega os resultados pendentes e envia a fila em ordem, até ela esvaziar ou uma
    /// tentativa falhar de modo passageiro. Banco ocupado também conta como falha passageira.
    fn flush(&mut self) -> Backlog {
        self.try_flush().unwrap_or(Backlog::Stuck)
    }

    fn try_flush(&mut self) -> Result<Backlog, StorageError> {
        for settled in self.outbox.settled()? {
            if !(self.notify)(&settled.client_message_id, settled.outcome) {
                break;
            }
            self.outbox.remove(settled.id)?;
        }
        while let Some(pending) = self.outbox.next()? {
            match (self.attempt)(&pending) {
                Attempt::Retry => return Ok(Backlog::Stuck),
                Attempt::Done(outcome) => {
                    self.outbox.settle(pending.id, outcome)?;
                    if (self.notify)(&pending.client_message_id, outcome) {
                        self.outbox.remove(pending.id)?;
                    }
                }
            }
        }
        Ok(Backlog::Empty)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, PoisonError};

    use super::*;
    use crate::storage::DatabaseKey;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const ACI: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    /// Quanto o teste espera por algo que acontece na thread.
    const WAIT: Duration = Duration::from_secs(5);

    fn outbox() -> Result<Outbox, StorageError> {
        let key = DatabaseKey::from_bytes(&[1; 32])?;
        Ok(Outbox::new(Arc::new(Database::open_in_memory(&key)?)))
    }

    fn peer() -> Result<Address, Box<dyn std::error::Error>> {
        Ok(Address::new(ACI, 2)?)
    }

    /// Uma linha da tabela: `client_message_id`, corpo e código do resultado.
    type Row = (Vec<u8>, Vec<u8>, Option<i64>);

    /// Lê toda a tabela.
    fn rows(outbox: &Outbox) -> Result<Vec<Row>, StorageError> {
        outbox.db.with(|c| {
            let mut select =
                c.prepare("SELECT client_message_id, body, outcome FROM outbox ORDER BY id")?;
            let rows = select.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
            rows.collect()
        })
    }

    #[test]
    fn fila_entrega_na_ordem_de_gravacao() -> TestResult {
        let outbox = outbox()?;
        let to = peer()?;
        let first = outbox.push(&to, b"um")?;
        let second = outbox.push(&to, b"dois")?;
        assert_ne!(first, second);

        let next = outbox.next()?.ok_or("fila vazia")?;
        assert_eq!(next.client_message_id, first);
        assert_eq!(next.to, to);
        assert_eq!(next.body.as_slice(), b"um");

        outbox.settle(next.id, Outcome::Sent)?;
        let next = outbox.next()?.ok_or("fila vazia")?;
        assert_eq!(next.client_message_id, second);
        outbox.settle(next.id, Outcome::Rejected(Rejection::SessionNotFound))?;
        assert!(outbox.next()?.is_none());
        Ok(())
    }

    #[test]
    fn client_message_id_e_um_uuid_v4() -> TestResult {
        let id = outbox()?.push(&peer()?, b"oi")?;
        let uuid = uuid::Uuid::from_bytes(id);
        assert_eq!(uuid.get_version(), Some(uuid::Version::Random));
        assert_eq!(uuid.get_variant(), uuid::Variant::RFC4122);
        Ok(())
    }

    #[test]
    fn resultado_apaga_o_corpo_e_espera_o_evento() -> TestResult {
        let outbox = outbox()?;
        let to = peer()?;
        let sent = outbox.push(&to, b"segredo")?;
        let rejected = outbox.push(&to, b"outro")?;
        for _ in 0..2 {
            let next = outbox.next()?.ok_or("fila vazia")?;
            let outcome = if next.client_message_id == sent {
                Outcome::Sent
            } else {
                Outcome::Rejected(Rejection::UnknownDestination)
            };
            outbox.settle(next.id, outcome)?;
        }
        assert_eq!(
            rows(&outbox)?,
            [
                (sent.to_vec(), Vec::new(), Some(0)),
                (rejected.to_vec(), Vec::new(), Some(2))
            ]
        );
        let settled = outbox.settled()?;
        assert_eq!(
            settled
                .iter()
                .map(|s| (s.client_message_id, s.outcome))
                .collect::<Vec<_>>(),
            [
                (sent, Outcome::Sent),
                (rejected, Outcome::Rejected(Rejection::UnknownDestination))
            ]
        );
        for settled in settled {
            outbox.remove(settled.id)?;
        }
        assert!(rows(&outbox)?.is_empty());
        Ok(())
    }

    #[test]
    fn codigos_de_resultado_vao_e_voltam() {
        for outcome in [
            Outcome::Sent,
            Outcome::Rejected(Rejection::InvalidEnvelope),
            Outcome::Rejected(Rejection::UnknownDestination),
            Outcome::Rejected(Rejection::SessionNotFound),
            Outcome::Rejected(Rejection::UntrustedIdentity),
        ] {
            assert_eq!(Outcome::from_code(outcome.code()), Some(outcome));
        }
        assert_eq!(Outcome::from_code(99), None);
    }

    /// O que a thread viu: cada tentativa (id e instante) e cada resultado entregue.
    #[derive(Default)]
    struct Log {
        attempts: Vec<(ClientMessageId, Instant)>,
        notified: Vec<(ClientMessageId, Outcome)>,
    }

    struct Harness {
        outbox: Outbox,
        log: Arc<Mutex<Log>>,
        listening: Arc<AtomicBool>,
        courier: Courier,
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl Harness {
        /// Courier sobre uma fila em memória; `script` responde as primeiras tentativas, e as
        /// seguintes são aceitas.
        fn start(
            backoff: Backoff,
            script: Vec<Attempt>,
        ) -> Result<Self, Box<dyn std::error::Error>> {
            let outbox = outbox()?;
            let log = Arc::new(Mutex::new(Log::default()));
            let script = Mutex::new(VecDeque::from(script));
            let listening = Arc::new(AtomicBool::new(true));
            let attempt: AttemptFn = {
                let log = log.clone();
                Box::new(move |pending| {
                    lock(&log)
                        .attempts
                        .push((pending.client_message_id, Instant::now()));
                    lock(&script)
                        .pop_front()
                        .unwrap_or(Attempt::Done(Outcome::Sent))
                })
            };
            let notify: NotifyFn = {
                let (log, listening) = (log.clone(), listening.clone());
                Box::new(move |id, outcome| {
                    let listening = listening.load(Ordering::SeqCst);
                    if listening {
                        lock(&log).notified.push((*id, outcome));
                    }
                    listening
                })
            };
            let courier = Courier::start(outbox.clone(), channel(), backoff, attempt, notify)?;
            Ok(Self {
                outbox,
                log,
                listening,
                courier,
            })
        }

        fn push(&self, body: &[u8]) -> Result<ClientMessageId, Box<dyn std::error::Error>> {
            let id = self.outbox.push(&peer()?, body)?;
            self.courier.wake().pushed();
            Ok(id)
        }

        fn wait_notified(&self, count: usize) -> Result<Vec<(ClientMessageId, Outcome)>, String> {
            let deadline = Instant::now() + WAIT;
            loop {
                let notified = lock(&self.log).notified.clone();
                if notified.len() >= count {
                    return Ok(notified);
                }
                if Instant::now() > deadline {
                    return Err(format!("{} de {count} resultados", notified.len()));
                }
                thread::sleep(Duration::from_millis(5));
            }
        }

        fn attempts(&self) -> Vec<(ClientMessageId, Instant)> {
            lock(&self.log).attempts.clone()
        }
    }

    const FAST: Backoff = Backoff {
        min: Duration::from_millis(20),
        max: Duration::from_millis(60),
    };

    #[test]
    fn envia_em_ordem_e_tira_da_fila() -> TestResult {
        let harness = Harness::start(FAST, Vec::new())?;
        let first = harness.push(b"um")?;
        let second = harness.push(b"dois")?;
        assert_eq!(
            harness.wait_notified(2)?,
            [(first, Outcome::Sent), (second, Outcome::Sent)]
        );
        assert!(rows(&harness.outbox)?.is_empty());
        Ok(())
    }

    #[test]
    fn falha_passageira_tenta_de_novo_com_backoff_exponencial() -> TestResult {
        let harness = Harness::start(
            FAST,
            vec![
                Attempt::Retry,
                Attempt::Retry,
                Attempt::Retry,
                Attempt::Retry,
            ],
        )?;
        let id = harness.push(b"oi")?;
        assert_eq!(harness.wait_notified(1)?, [(id, Outcome::Sent)]);

        let attempts = harness.attempts();
        assert_eq!(attempts.len(), 5);
        assert!(attempts.iter().all(|(attempt, _)| *attempt == id));
        let gaps: Vec<Duration> = attempts.windows(2).map(|w| w[1].1 - w[0].1).collect();
        // 20ms, 40ms e depois o teto de 60ms.
        for (gap, expected) in gaps.iter().zip([20, 40, 60, 60]) {
            assert!(*gap >= Duration::from_millis(expected), "{gaps:?}");
        }
        Ok(())
    }

    #[test]
    fn falha_passageira_para_a_fila_sem_pular_a_mensagem_da_frente() -> TestResult {
        let harness = Harness::start(FAST, vec![Attempt::Retry])?;
        let first = harness.push(b"um")?;
        let second = harness.push(b"dois")?;
        assert_eq!(
            harness.wait_notified(2)?,
            [(first, Outcome::Sent), (second, Outcome::Sent)]
        );
        let order: Vec<ClientMessageId> = harness.attempts().iter().map(|a| a.0).collect();
        assert_eq!(order, [first, first, second]);
        Ok(())
    }

    #[test]
    fn retry_acorda_na_hora_sem_esperar_o_backoff() -> TestResult {
        let slow = Backoff {
            min: Duration::from_secs(60),
            max: Duration::from_secs(60),
        };
        let harness = Harness::start(slow, vec![Attempt::Retry])?;
        let id = harness.push(b"oi")?;
        let deadline = Instant::now() + WAIT;
        while harness.attempts().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        // Mensagem nova não fura o backoff; a reconexão, sim.
        let other = harness.push(b"outra")?;
        thread::sleep(Duration::from_millis(50));
        assert_eq!(harness.attempts().len(), 1);
        harness.courier.wake().retry();
        assert_eq!(
            harness.wait_notified(2)?,
            [(id, Outcome::Sent), (other, Outcome::Sent)]
        );
        Ok(())
    }

    #[test]
    fn recusa_definitiva_sai_da_fila_e_segue_para_a_proxima() -> TestResult {
        let rejected = Outcome::Rejected(Rejection::UnknownDestination);
        let harness = Harness::start(FAST, vec![Attempt::Done(rejected)])?;
        let first = harness.push(b"um")?;
        let second = harness.push(b"dois")?;
        assert_eq!(
            harness.wait_notified(2)?,
            [(first, rejected), (second, Outcome::Sent)]
        );
        assert_eq!(harness.attempts().len(), 2);
        Ok(())
    }

    #[test]
    fn sem_assinante_o_resultado_fica_ate_alguem_ouvir() -> TestResult {
        let harness = Harness::start(FAST, Vec::new())?;
        harness.listening.store(false, Ordering::SeqCst);
        let id = harness.push(b"oi")?;
        let deadline = Instant::now() + WAIT;
        while rows(&harness.outbox)?
            .first()
            .and_then(|row| row.2)
            .is_none()
        {
            if Instant::now() > deadline {
                return Err("sem resultado".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        // Enviada uma vez só; o corpo já foi apagado.
        assert_eq!(rows(&harness.outbox)?, [(id.to_vec(), Vec::new(), Some(0))]);

        harness.listening.store(true, Ordering::SeqCst);
        harness.courier.wake().retry();
        assert_eq!(harness.wait_notified(1)?, [(id, Outcome::Sent)]);
        assert_eq!(harness.attempts().len(), 1);
        assert!(rows(&harness.outbox)?.is_empty());
        Ok(())
    }

    #[test]
    fn fila_gravada_antes_do_courier_sai_quando_ele_sobe() -> TestResult {
        let outbox = outbox()?;
        let id = outbox.push(&peer()?, b"offline")?;
        let notified = Arc::new(Mutex::new(Vec::new()));
        let notify: NotifyFn = {
            let notified = notified.clone();
            Box::new(move |id, outcome| {
                lock(&notified).push((*id, outcome));
                true
            })
        };
        let _courier = Courier::start(
            outbox.clone(),
            channel(),
            FAST,
            Box::new(|_| Attempt::Done(Outcome::Sent)),
            notify,
        )?;
        let deadline = Instant::now() + WAIT;
        while lock(&notified).is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(*lock(&notified), [(id, Outcome::Sent)]);
        Ok(())
    }

    #[test]
    fn courier_para_ao_sair_de_escopo() -> TestResult {
        let Harness {
            outbox,
            log,
            courier,
            ..
        } = Harness::start(FAST, Vec::new())?;
        let wake = courier.wake().clone();
        drop(courier);
        thread::sleep(Duration::from_millis(50));
        outbox.push(&peer()?, b"depois")?;
        wake.pushed();
        wake.retry();
        thread::sleep(Duration::from_millis(50));
        assert!(lock(&log).attempts.is_empty());
        Ok(())
    }
}
