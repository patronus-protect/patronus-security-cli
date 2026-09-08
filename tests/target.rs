use patronus_security_scanner::target::{find_repo_root, ScanTarget, TargetKind};

#[test]
fn finds_git_directory_and_worktree_file() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::create_dir(temp.path().join(".git")).unwrap();
    assert_eq!(find_repo_root(&nested).unwrap(), temp.path());

    let second = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(second.path().join("nested")).unwrap();
    std::fs::write(second.path().join(".git"), "gitdir: elsewhere").unwrap();
    assert_eq!(
        find_repo_root(&second.path().join("nested")).unwrap(),
        second.path()
    );
}

#[cfg(unix)]
#[test]
fn explicit_file_symlink_is_retained_for_safe_skip() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let real = temp.path().join("real.txt");
    let link = temp.path().join("link.txt");
    std::fs::write(&real, "safe").unwrap();
    symlink(&real, &link).unwrap();
    let target = ScanTarget::resolve(TargetKind::File, &link).unwrap();
    assert_eq!(target.explicit_file.as_deref(), Some(link.as_path()));
}
