use std::io;
use std::path::Path;

/// Replace a file atomically: write a temporary sibling, copy the original
/// permission mode onto it, then rename. The file must already exist — it
/// is never created.
pub fn replace_file_atomic(path: &str, content: &str) -> io::Result<()> {
    let path = Path::new(path);
    let metadata = std::fs::metadata(path)?;
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "file path has no parent directory",
        )
    })?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file path has no file name"))?;
    let temp = tempfile_named(dir, file_name)?;
    let result = std::fs::write(&temp, content)
        .and_then(|()| std::fs::set_permissions(&temp, metadata.permissions()))
        .and_then(|()| std::fs::rename(&temp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn tempfile_named(dir: &Path, file_name: &str) -> io::Result<std::path::PathBuf> {
    for attempt in 0..100u32 {
        let candidate = dir.join(format!(".{file_name}.{attempt}.tmp"));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate a temporary file name",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_content_and_preserves_mode() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        std::fs::write(&path, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        replace_file_atomic(path.to_str().unwrap(), "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_file_is_an_error_not_a_creation() {
        let dir =
            std::env::temp_dir().join(format!("subscription-write-missing-{}", std::process::id()));
        let path = dir.join("does-not-exist.toml");
        assert!(replace_file_atomic(path.to_str().unwrap(), "x").is_err());
        assert!(!path.exists());
    }
}
