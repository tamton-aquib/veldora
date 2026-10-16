use std::path::Path;

pub enum FileType {
    Zip,
    Pdf,
    Hash,
    NotSupported,
    NotFound,
}

pub fn detect(path: &Path) -> FileType {
    match path.extension().and_then(|e| e.to_str()) {
        Some(e) => match e.to_ascii_lowercase().as_str() {
            "zip" => {
                if path.exists() {
                    FileType::Zip
                } else {
                    FileType::NotFound
                }
            }
            "pdf" => {
                if path.exists() {
                    FileType::Pdf
                } else {
                    FileType::NotFound
                }
            }
            _ => FileType::NotSupported,
        },
        None => {
            let s = path.to_string_lossy();
            let is_hex = !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit());
            if is_hex {
                FileType::Hash
            } else {
                FileType::NotSupported
            }
        }
    }
}
