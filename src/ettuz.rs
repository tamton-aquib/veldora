//! # Zip bruteforcing module
//!
//! For bruteforcing encrypted zip files.
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};
use zip::ZipArchive;

// For ZIP files
/// Bruteforces the password for a zip file.
///
/// # Examples
///
/// match ettuz(filename, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettuz(filename: &str, pass_list: &str) -> Option<String> {
    let reader = BufReader::new(
        File::open(pass_list).expect("Error on reading password file."),
    );
    let passwords: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let mut possible_passes: Vec<String> = Vec::new();

    let bar = ProgressBar::new(passwords.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
            .unwrap(),
    );

    let results: Vec<Option<String>> = passwords
        .par_iter()
        .map(|pass| {
            bar.inc(1);
            let zip_file = File::open(filename).expect("Could not open the zip file.");
            let mut archive = ZipArchive::new(&zip_file).expect("Error Reading the zip file.");
            let result = match archive.by_index_decrypt(0, pass.as_bytes()) {
                Ok(Ok(_)) => Some(pass.clone()),
                _ => None,
            };
            result
        })
        .collect();

    for r in results {
        if let Some(pass) = r {
            possible_passes.push(pass);
        }
    }

    bar.finish();
    if !possible_passes.is_empty() {
        Some(possible_passes.join("\n"))
    } else {
        None
    }
}
