//! Testes de `scripts/mobile-size`, o gate de tamanho de `make build-mobile`.
//!
//! Os artefatos são arquivos esparsos com o tamanho pedido; o script só lê o tamanho.
#![cfg(unix)]

use std::error::Error;
use std::fs::{self, File};
use std::path::Path;
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn Error>>;

const ABIS: [&str; 3] = ["arm64-v8a", "armeabi-v7a", "x86_64"];
const LIMIT: u64 = 10 * 1024 * 1024;

fn artifact(path: &Path, bytes: u64) -> TestResult {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    File::create(path)?.set_len(bytes)?;
    Ok(())
}

fn android(dist: &Path, abi: &str, bytes: u64) -> TestResult {
    artifact(
        &dist.join("android").join(abi).join("libfalaai_core.so"),
        bytes,
    )
}

fn mobile_size(dist: &Path) -> Result<Output, Box<dyn Error>> {
    Ok(
        Command::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/mobile-size"))
            .arg(dist)
            .arg(LIMIT.to_string())
            .args(ABIS)
            .output()?,
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn passa_com_todas_as_abis_dentro_do_limite() -> TestResult {
    let dist = tempfile::tempdir()?;
    for abi in ABIS {
        android(dist.path(), abi, LIMIT)?;
    }
    let out = mobile_size(dist.path())?;
    assert!(out.status.success(), "{}", stderr(&out));
    for abi in ABIS {
        assert!(
            stdout(&out).contains(&format!("android {abi} {LIMIT} bytes (10.00 MB)")),
            "{}",
            stdout(&out)
        );
    }
    assert!(stdout(&out).contains("FALAAI-SIZE: PASS"));
    Ok(())
}

#[test]
fn falha_quando_uma_abi_passa_do_limite() -> TestResult {
    let dist = tempfile::tempdir()?;
    android(dist.path(), "arm64-v8a", 1)?;
    android(dist.path(), "armeabi-v7a", 1)?;
    android(dist.path(), "x86_64", LIMIT + 1)?;
    let out = mobile_size(dist.path())?;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains(&format!(
            "FALAAI-SIZE: FAIL abi=x86_64 bytes={} limite={LIMIT}",
            LIMIT + 1
        )),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn falha_quando_falta_uma_abi() -> TestResult {
    let dist = tempfile::tempdir()?;
    android(dist.path(), "arm64-v8a", 1)?;
    android(dist.path(), "x86_64", 1)?;
    let out = mobile_size(dist.path())?;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("FALAAI-SIZE: FAIL abi=armeabi-v7a ausente"),
        "{}",
        stderr(&out)
    );
    Ok(())
}

#[test]
fn xcframework_e_informativo_e_nao_entra_no_limite() -> TestResult {
    let dist = tempfile::tempdir()?;
    for abi in ABIS {
        android(dist.path(), abi, 1)?;
    }
    for slice in ["ios-arm64", "ios-arm64-simulator"] {
        artifact(
            &dist
                .path()
                .join("FalaaiCore.xcframework")
                .join(slice)
                .join("libfalaai_core.a"),
            LIMIT * 3,
        )?;
    }
    let out = mobile_size(dist.path())?;
    assert!(out.status.success(), "{}", stderr(&out));
    for slice in ["ios-arm64", "ios-arm64-simulator"] {
        assert!(
            stdout(&out).contains(&format!("ios {slice} {} bytes", LIMIT * 3)),
            "{}",
            stdout(&out)
        );
    }
    Ok(())
}
