//! falaai-core: núcleo do FalaAí.
//!
//! A libsignal fica isolada em `protocol` (ADR-0001); o resto do core usa só as traits de lá.

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "consumido pela API flutter_rust_bridge (flc-8lr)")
)]
mod protocol;
