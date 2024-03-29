//! # Pdf bruteforcing module
//!
//! For bruteforcing encrypted pdf files.

use indicatif::{ProgressBar, ProgressStyle};
use pdf::file::File;
use rayon::prelude::*;
use std::fs;

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
    let pass_file = fs::read_to_string(pass_file_name).expect("Couldnt open password file!");
    let pass_list: Vec<&str> = pass_file.lines().collect();
    let bar = ProgressBar::new(pass_list.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
            .unwrap(),
    );

    let results = pass_list
        .par_iter()
        .find_first(|pass| {
            bar.inc(1);
            let f = File::open_password(filename, pass.as_bytes());
            f.is_ok()
        })
        .map(|pass| pass.to_string());

    results.into_iter().next()
}
