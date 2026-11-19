use std::io::Read;

#[test]
fn windows_archive_includes_runtime_and_vendor_license() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("scanner.exe");
    std::fs::write(&binary, b"test executable").unwrap();
    std::fs::write(root.path().join("DirectML.dll"), b"test runtime").unwrap();
    std::fs::write(root.path().join("unrelated.dll"), b"not a release asset").unwrap();
    let out = root.path().join("dist");
    assert_cmd::Command::new(env!("CARGO_BIN_EXE_package-plugins"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(&binary)
        .arg("x86_64-pc-windows-msvc")
        .arg(&out)
        .assert()
        .success();
    let path = out.join(format!(
        "patronus-security-scanner-{}-x86_64-pc-windows-msvc.zip",
        env!("CARGO_PKG_VERSION")
    ));
    let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
    let mut runtime = Vec::new();
    archive
        .by_name("DirectML.dll")
        .unwrap()
        .read_to_end(&mut runtime)
        .unwrap();
    assert_eq!(runtime, b"test runtime");
    let mut license = String::new();
    archive
        .by_name("licenses/DirectML-LICENSE.txt")
        .unwrap()
        .read_to_string(&mut license)
        .unwrap();
    assert!(license.contains("MICROSOFT SOFTWARE LICENSE TERMS"));
    assert!(archive.by_name("patronus-security-scanner.exe").is_ok());
    assert!(archive.by_name("unrelated.dll").is_err());
}

#[test]
fn windows_packaging_rejects_a_missing_runtime_companion() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("scanner.exe");
    std::fs::write(&binary, b"test executable").unwrap();
    assert_cmd::Command::new(env!("CARGO_BIN_EXE_package-plugins"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .arg(&binary)
        .arg("x86_64-pc-windows-msvc")
        .arg(root.path().join("dist"))
        .assert()
        .failure();
}
