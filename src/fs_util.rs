use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::error::DynError;

pub fn ensure_dir(path: &Path) -> Result<(), DynError> {
    fs::create_dir_all(path)?;
    Ok(())
}

pub fn write_json(path: &Path, value: &impl Serialize) -> Result<(), DynError> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

pub fn workspace_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::new();
    for part in parts {
        path.push(part);
    }
    path
}
