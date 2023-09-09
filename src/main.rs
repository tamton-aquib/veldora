//! # Veldora
//!
//! This program can bruteforce (with a dictionary attack) on:
//! - PDF
//! - ZIP
//! - Hashes like md5,sha1,224,256,384,512
//!
//! Some Exposed functions are:
//! - ettuz (for zips)
//! - ettup (for pdfs)
//! - ettuh (for hashes)

use colored::Colorize;
use std::env;
use std::path::Path;
use veldora::{ettuh, ettup, ettuz};

enum Status {
    Ettuz,
    Ettup,
    Ettuh,
    FileNotSupported,
    FileNotFound,
}

fn parse_type(path: &Path) -> Status {
    match path.extension() {
        Some(e) => match e.to_str().unwrap() {
            "zip" => {
                if path.exists() {
                    Status::Ettuz
                } else {
                    Status::FileNotFound
                }
            }
            "pdf" => {
                if path.exists() {
                    Status::Ettup
                } else {
                    Status::FileNotFound
                }
            }
            _ => Status::FileNotSupported,
        },
        None => {
            let char_list: Vec<char> = path.to_string_lossy().chars().collect();
            let is_hex = char_list.iter().all(|&x| "1234567890abcdef".contains(x));

            if is_hex {
                Status::Ettuh
            } else {
                Status::FileNotSupported
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!(
            "{}",
            "Usage: veldora <filename> <password_list>".bright_green()
        );
        return;
    }

    let file_or_hash = &args[1];
    let pass_file = &args[2];

    let path = Path::new(file_or_hash);

    let result = match parse_type(path) {
        Status::Ettuz => ettuz::ettuz(file_or_hash, pass_file),
        Status::Ettup => ettup::ettup(file_or_hash, pass_file),
        Status::Ettuh => ettuh::ettuh(file_or_hash, pass_file),

        Status::FileNotSupported => Some("Filetype not supported!".to_string()),
        Status::FileNotFound => Some("Target file not Found!".to_string()),
    };

    match result {
        Some(pass) => println!("Possible Passwords:\n{}", pass.bright_green()),
        None => println!("Couldnt get pass!"),
    }
}
