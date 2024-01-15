use std::io::{Error, Write};
use std::path::PathBuf;
use std::time::SystemTime;
use std::{fs::File, io::Read};

use tokio::fs;

// Method to read the file and return the contents as Vec<u8>
pub fn read_file_as_vec(path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    Ok(contents)
}

// Method to read the file and return the contents as String
pub fn read_file_as_string(path: &str) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// Method to write the contents to a file
pub fn write_to_file(
    path: &str,
    contents: &[u8],
) -> Result<(), std::io::Error> {
    let mut file = File::create(path)?;
    file.write_all(contents)?;
    Ok(())
}

// Additional helper function to find the latest file with a specific extension
pub async fn find_latest_file_with_extension(
    dir_path: &str,
    extension: &str,
) -> Result<PathBuf, Error> {
    let mut latest: Option<(SystemTime, PathBuf)> = None;

    let mut entries = fs::read_dir(dir_path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some(extension) {
            let metadata = fs::metadata(&path).await?;
            let modified = metadata.modified()?;
            if latest
                .clone()
                .map(|(time, _)| modified > time)
                .unwrap_or(true)
            {
                latest = Some((modified, path));
            }
        }
    }

    latest.map(|(_, path)| path).ok_or_else(|| {
        Error::new(
            std::io::ErrorKind::NotFound,
            format!("No .{} files found in directory {}", extension, dir_path),
        )
    })
}
