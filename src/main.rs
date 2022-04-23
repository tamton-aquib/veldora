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

mod ettuh;
mod ettup;
mod ettuz;

fn parse_type(path: &Path) -> u8 {
    match path.extension() {
        Some(e) => match e.to_str().unwrap() {
            "zip" => {
                if path.exists() {
                    1 as u8
                } else {
                    5 as u8
                }
            }
            "pdf" => {
                if path.exists() {
                    2 as u8
                } else {
                    5 as u8
                }
            }
            _ => 4 as u8,
        },
        None => {
            let char_list: Vec<char> = path.to_string_lossy().chars().collect();
            let is_hex = char_list.iter().all(|&x| "1234567890abcdef".contains(x));

            if is_hex {
                3 as u8
            } else {
                4 as u8
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
    let pass_list = &args[2];

    let path = Path::new(file_or_hash);
    let status: u8 = parse_type(path);

    let result = match status {
        1 => ettuz::ettuz(file_or_hash, &pass_list),
        2 => ettup::ettup(file_or_hash, &pass_list),
        3 => ettuh::ettuh(file_or_hash, &pass_list),

        4 => Some("Filetype not supported!".to_string()),
        5 => Some("Target file not Found!".to_string()),
        _ => Some("Unknown Operation!".to_string()),
    };

    match result {
        Some(pass) => println!("Possible Passwords: {}", pass.bright_green()),
        None => println!("Couldnt get pass!"),
    }
}
