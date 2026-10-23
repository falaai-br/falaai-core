//! falaai-core: núcleo do FalaAí.
//!
//! A libsignal fica isolada em `protocol` (ADR-0001); o resto do core usa só as traits de lá.
//! `storage` guarda o banco local cifrado (SQLCipher), sem conhecer a libsignal. `transport`
//! fala com o servidor (WebSocket e HTTPS), também sem conhecê-la. `api` é a superfície exposta
//! ao Flutter, e `frb_generated` a cola FFI gerada a partir dela.

pub mod api;
// Gerado por 'make bindings'. Exportar funções C exige `#[unsafe(no_mangle)]`, por isso o
// `unsafe_code` liberado só aqui; o código escrito à mão segue sob `deny`.
#[allow(
    unsafe_code,
    missing_docs,
    clippy::all,
    clippy::pedantic,
    clippy::restriction
)]
mod frb_generated;
mod protocol;
mod storage;
mod transport;
