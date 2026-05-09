use std::path::Path;

pub enum FileType {
    Zip,
    Pdf,
    Hash,
    NotSupported,
    NotFound,
}

pub fn detect(path: &Path) -> FileType {
    match path.extension() {
        Some(e) => match e.to_str().unwrap() {
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
            let is_hex = s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
            if is_hex {
                FileType::Hash
            } else {
                FileType::NotSupported
            }
        }
    }
}
