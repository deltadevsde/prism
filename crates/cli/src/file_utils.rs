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
        return path.replacen("~", &home.to_string_lossy(), 1);
    }
    path.to_string()
}
