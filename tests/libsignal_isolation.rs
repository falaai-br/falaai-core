//! A libsignal só pode ser usada dentro de `src/protocol/` (ADR-0001): a API Rust dela não tem
//! semver, e o isolamento mantém um upgrade contido num módulo.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

#[test]
fn libsignal_so_aparece_em_src_protocol() -> Result<(), Box<dyn Error>> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let protocol = src.join("protocol");
    let mut files = Vec::new();
    rust_files(&src, &mut files)?;
    assert!(
        files.iter().any(|f| f.starts_with(&protocol)),
        "src/protocol/ sumiu"
    );

    let mut offenders = Vec::new();
    for file in files.iter().filter(|f| !f.starts_with(&protocol)) {
        let source = fs::read_to_string(file)?;
        if ["libsignal_protocol", "zkgroup"]
            .iter()
            .any(|krate| source.contains(krate))
        {
            offenders.push(file);
        }
    }
    assert!(
        offenders.is_empty(),
        "libsignal fora de src/protocol/: {offenders:?}"
    );
    Ok(())
}
