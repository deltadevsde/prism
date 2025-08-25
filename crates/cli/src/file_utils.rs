use anyhow::{Context, Result};
use dirs::home_dir;
use std::{fs, path::Path};

pub fn ensure_file_directory_exists(config_path: impl AsRef<Path>) -> Result<()> {
    // If the path already exists, we're good
    if config_path.as_ref().exists() {
        return Ok(());
    }
    // Create parent directories if they don't exist
    if let Some(parent) = config_path.as_ref().parent() {
        if parent.as_os_str().is_empty() {
            // Relative file in current directory; nothing to create
            return Ok(());
        }
        return fs::create_dir_all(parent).context("Failed to create config directory");
    }
    // No parent (unlikely), nothing to create
    Ok(())
}

pub fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/")
        && let Some(home) = home_dir()
    {
        return path.replacen('~', &home.to_string_lossy(), 1);
    }
    path.to_string()
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use dirs::home_dir;
    use std::fs;
    use tempfile::TempDir;

    use crate::file_utils::{ensure_file_directory_exists, expand_tilde};

    #[test]
    fn test_ensure_file_directory_exists_existing_path() {
        let temp_dir = TempDir::new().unwrap();
        let existing_file = temp_dir.path().join("existing.txt");
        fs::write(&existing_file, "test").unwrap();

        let result = ensure_file_directory_exists(&existing_file);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_file_directory_exists_creates_parent_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let nested_file = temp_dir.path().join("nested").join("deep").join("file.txt");

        let result = ensure_file_directory_exists(&nested_file);
        assert!(result.is_ok());
        assert!(nested_file.parent().unwrap().exists());
    }

    #[test]
    fn test_ensure_file_directory_exists_relative_path() {
        let result = ensure_file_directory_exists("file.txt");
        assert!(result.is_ok());
    }

    #[test]
    fn test_expand_tilde_with_home() {
        let result = expand_tilde("~/Documents/test.txt");
        if let Some(home) = home_dir() {
            let expected = format!("{}/Documents/test.txt", home.to_string_lossy());
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_expand_tilde_without_tilde() {
        let path = "/absolute/path/test.txt";
        let result = expand_tilde(path);
        assert_eq!(result, path);
    }

    #[test]
    fn test_expand_tilde_relative_path() {
        let path = "relative/path/test.txt";
        let result = expand_tilde(path);
        assert_eq!(result, path);
    }

    #[test]
    fn test_expand_tilde_just_tilde() {
        let result = expand_tilde("~");
        assert_eq!(result, "~"); // Should not expand standalone tilde
    }

    #[test]
    fn test_expand_tilde_middle_of_path() {
        let path = "/some/~/path";
        let result = expand_tilde(path);
        assert_eq!(result, path); // Should not expand tilde in middle
    }
}
