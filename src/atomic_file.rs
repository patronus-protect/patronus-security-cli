use std::path::Path;

#[cfg(not(windows))]
pub(crate) fn replace(source: &Path, target: &Path) -> std::io::Result<()> {
    std::fs::rename(source, target)
}

#[cfg(windows)]
pub(crate) fn replace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let target = target
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            target.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::replace;

    #[test]
    fn moves_into_a_missing_target() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.tmp");
        let target = directory.path().join("target.txt");
        std::fs::write(&source, b"new").unwrap();

        replace(&source, &target).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!source.exists());
    }

    #[test]
    fn replaces_an_existing_target() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.tmp");
        let target = directory.path().join("target.txt");
        std::fs::write(&source, b"new").unwrap();
        std::fs::write(&target, b"old").unwrap();

        replace(&source, &target).unwrap();

        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert!(!source.exists());
    }
}
