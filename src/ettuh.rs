use md5::{Md5, Digest};
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use indicatif::ProgressBar;
use std::fs;

// For hashes
pub fn ettuh(query: &str, pass_list: &str) -> Option<String> {
    let pass_file = match fs::read_to_string(pass_list) {
        Ok(file) => file,
        Err(_) => {
            println!("Could not read file. File not encoded in utf-8");
            return None
        }
    };

    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    for pass in pass_list.iter() {
        bar.inc(1);

        // TODO: maybe support more hashes?
        let pass_hash = match query.len() {
            32 => format!("{:x}", Md5::digest(pass.as_bytes())),
            40 => format!("{:x}", Sha1::digest(pass.as_bytes())),
            56 => format!("{:x}", Sha224::digest(pass.as_bytes())),
            64 => format!("{:x}", Sha256::digest(pass.as_bytes())),
            96 => format!("{:x}", Sha384::digest(pass.as_bytes())),
            128 => format!("{:x}", Sha512::digest(pass.as_bytes())),
            _ => "NULL".to_string()
        };

        // TODO: convert to match?
        if pass_hash == query {
            bar.finish();
            return Some(format!("\nGot matching hash: {}", pass));
        } else if pass_hash == "NULL" {
            return Some("No compatible hash found! :(".to_string());
        } else {
            continue;
        }
    }

    bar.finish();
    // println!("\nCouldnt find a match! :(");
    None
}
