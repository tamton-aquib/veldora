use colored::Colorize;
use std::env;
use std::path::Path;
use veldora::{ettuh, ettup, ettuz};

mod cli;
use cli::FileType;

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

    let result = match cli::detect(path) {
        FileType::Zip => ettuz::ettuz(file_or_hash, pass_file),
        FileType::Pdf => match ettup::ettup(file_or_hash, pass_file) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{}", e);
                Some(String::new())
            }
        },
        FileType::Hash => ettuh::ettuh(file_or_hash, pass_file),
        FileType::NotSupported => Some("Filetype not supported!".to_string()),
        FileType::NotFound => Some("Target file not Found!".to_string()),
    };

    match result {
        Some(pass) if !pass.is_empty() => println!("Possible Passwords:\n{}", pass.bright_green()),
        None => println!("Couldnt get pass!"),
        _ => {}
    }
}
