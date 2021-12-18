//! # Pdf bruteforcing module
//!
//! For bruteforcing encrypted pdf files.
use indicatif::ProgressBar;
use pdf::file::File;
use std::fs;

// for PDF files
/// Bruteforces the password for a pdf file.
///
/// # Examples
///
/// ```
/// use veldora::ettup;
///
/// ... rest of your code.
/// match ettup(filename, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettup(filename: &str, pass_file_name: &str) -> Option<String> {
    let pass_file = fs::read_to_string(pass_file_name).expect("COULDN'T OPEN PASSWORD FILE");
    let pass_list: Vec<&str> = pass_file.split('\n').collect();
    let bar = ProgressBar::new(pass_list.len() as u64);

    for pass in pass_list.iter() {
        bar.inc(1);
        let f = File::open_password(filename, pass.as_bytes());

        match &f {
            Ok(_) => {
                bar.finish();
                return Some(pass.to_string());
            }
            Err(_) => {}
        };
    }
    bar.finish();
    None
}
