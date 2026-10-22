//! Testes de integração dos git hooks versionados em `.githooks/`.
//!
//! Garantem que o pipeline local bloqueia o que deve bloquear: mensagem fora de Conventional
//! Commits no `commit-msg` e falha do `make` no `pre-commit` e no `pre-push`. O `make` é
//! substituído pelo stub em `tests/fixtures/bin/make`, que registra os argumentos recebidos.
#![cfg(unix)]

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

type TestResult = Result<(), Box<dyn Error>>;

const ZERO_SHA: &str = "0000000000000000000000000000000000000000";
const SOME_SHA: &str = "1111111111111111111111111111111111111111";

fn repo_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Diretório temporário exclusivo de um teste, apagado no drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> std::io::Result<Self> {
        let dir = std::env::temp_dir().join(format!("falaai-hooks-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }

    fn make_log(&self) -> PathBuf {
        self.0.join("make.log")
    }

    /// Chamadas ao stub de make, uma por linha.
    fn make_calls(&self) -> std::io::Result<Vec<String>> {
        match fs::read_to_string(self.make_log()) {
            Ok(log) => Ok(log.lines().map(str::to_owned).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Roda um hook com o stub de make na frente do PATH e `stdin` como entrada.
fn run_hook(
    scratch: &Scratch,
    name: &str,
    args: &[&Path],
    make_exit: i32,
    stdin: &str,
) -> Result<Output, Box<dyn Error>> {
    let path = std::env::join_paths(std::iter::once(repo_path("tests/fixtures/bin")).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))?;
    let mut child = Command::new(repo_path(".githooks").join(name))
        .args(args)
        .current_dir(&scratch.0)
        .env("PATH", path)
        .env("FALAAI_TEST_MAKE_LOG", scratch.make_log())
        .env("FALAAI_TEST_MAKE_EXIT", make_exit.to_string())
        .env_remove("FALAAI_SKIP_HOOKS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut input) = child.stdin.take() {
        input.write_all(stdin.as_bytes())?;
    }
    Ok(child.wait_with_output()?)
}

fn commit_msg(scratch: &Scratch, message: &str) -> Result<Output, Box<dyn Error>> {
    let file = scratch.0.join("COMMIT_EDITMSG");
    fs::write(&file, message)?;
    run_hook(scratch, "commit-msg", &[&file], 0, "")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn commit_msg_aceita_conventional_commits() -> TestResult {
    let scratch = Scratch::new("msg-ok")?;
    for message in [
        "feat(keys): consumir one-time prekey no fetch\n",
        "fix: corrige recibo duplicado (flc-3zz)\n\nCorpo livre.\n",
        "refactor(storage/sqlcipher)!: troca o esquema\n",
        "Merge branch 'main' into polecat/x\n",
        "fixup! feat: algo\n",
    ] {
        let out = commit_msg(&scratch, message)?;
        assert!(
            out.status.success(),
            "recusou {message:?}: {}",
            stderr(&out)
        );
    }
    Ok(())
}

#[test]
fn commit_msg_recusa_mensagem_fora_do_padrao() -> TestResult {
    let scratch = Scratch::new("msg-bad")?;
    let too_long = format!("feat: {}\n", "a".repeat(101));
    for message in [
        "corrige bug\n",
        "Feat: maiúscula no tipo\n",
        "feat:sem espaço\n",
        "feat(Keys): escopo com maiúscula\n",
        "wip(keys): tipo inexistente\n",
        "feat: \n",
        "\nfeat: primeira linha vazia\n",
        "",
        too_long.as_str(),
    ] {
        let out = commit_msg(&scratch, message)?;
        assert!(!out.status.success(), "aceitou {message:?}");
        assert!(
            stderr(&out).contains("FALAAI-HOOK: FAIL gate=commit-msg"),
            "{}",
            stderr(&out)
        );
    }
    Ok(())
}

#[test]
fn pre_commit_bloqueia_quando_check_fast_falha() -> TestResult {
    let scratch = Scratch::new("pre-commit-fail")?;
    let out = run_hook(&scratch, "pre-commit", &[], 2, "")?;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("FALAAI-HOOK: FAIL gate=check-fast"),
        "{}",
        stderr(&out)
    );
    assert_eq!(scratch.make_calls()?, ["-s check-fast"]);
    Ok(())
}

#[test]
fn pre_commit_passa_quando_check_fast_passa() -> TestResult {
    let scratch = Scratch::new("pre-commit-ok")?;
    let out = run_hook(&scratch, "pre-commit", &[], 0, "")?;
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(scratch.make_calls()?, ["-s check-fast"]);
    Ok(())
}

#[test]
fn pre_push_bloqueia_quando_check_falha() -> TestResult {
    let scratch = Scratch::new("pre-push-fail")?;
    let refs = format!("refs/heads/x {SOME_SHA} refs/heads/x {ZERO_SHA}\n");
    let out = run_hook(&scratch, "pre-push", &[], 2, &refs)?;
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("FALAAI-HOOK: FAIL gate=check"),
        "{}",
        stderr(&out)
    );
    assert_eq!(scratch.make_calls()?, ["-s check"]);
    Ok(())
}

#[test]
fn pre_push_passa_quando_check_passa() -> TestResult {
    let scratch = Scratch::new("pre-push-ok")?;
    let refs = format!(
        "(delete) {ZERO_SHA} refs/heads/velha {SOME_SHA}\nrefs/heads/x {SOME_SHA} refs/heads/x {SOME_SHA}\n"
    );
    let out = run_hook(&scratch, "pre-push", &[], 0, &refs)?;
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(scratch.make_calls()?, ["-s check"]);
    Ok(())
}

#[test]
fn pre_push_ignora_push_que_so_apaga_branch() -> TestResult {
    let scratch = Scratch::new("pre-push-delete")?;
    let refs = format!("(delete) {ZERO_SHA} refs/heads/velha {SOME_SHA}\n");
    let out = run_hook(&scratch, "pre-push", &[], 2, &refs)?;
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(scratch.make_calls()?.is_empty());
    Ok(())
}
