//! # Pdf bruteforcing module
//!
//! For bruteforcing encrypted pdf files.

use indicatif::{ProgressBar, ProgressStyle};
use pdf::file::File as PdfFile;
use rayon::prelude::*;
use std::fs::File;
use std::io::{BufRead, BufReader};

// for PDF files
/// Bruteforces the password for a pdf file.
///
/// # Examples
///
/// ```
/// use veldora::ettup;
///
/// // ... rest of your code.
/// match ettup(filename, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettup(filename: &str, pass_file_name: &str) -> Option<String> {
    let reader = BufReader::new(
        File::open(pass_file_name).expect("Couldnt open password file!"),
    );
    let pass_list: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let bar = ProgressBar::new(pass_list.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
            .unwrap(),
    );

    pass_list
        .par_iter()
        .find_first(|pass| {
            bar.inc(1);
            PdfFile::open_password(filename, pass.as_bytes()).is_ok()
        })
        .map(|pass| pass.to_string())
}
