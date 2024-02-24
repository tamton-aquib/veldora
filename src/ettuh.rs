//! # Hash bruteforcing module
//!
//! For bruteforcing popular hashes. Will add more hashtypes soon.

use indicatif::{ProgressBar, ProgressStyle};
use md5::{Digest, Md5};
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::fs;
use tiger::Tiger;

// For hashes
/// Bruteforces the password for hashes like md5,Sha512,etc.
///
/// # Examples
///
/// ```
/// use veldora::ettuh;
///
/// // ... rest of your code.
/// match ettuh(hash_string, password_list) {
///     Some(pass) => println!("Possible password: {}", pass),
///     None => println!("Couldn't get password!")
/// };
/// ```
pub fn ettuh(query: &str, pass_list: &str) -> Option<String> {
    let pass_file = fs::read_to_string(pass_list)
        .expect("Error reading the file. Make sure its UTF-8 encoded!");

    let pass_list: Vec<&str> = pass_file.lines().collect();
    let bar = ProgressBar::new(pass_list.len() as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
            .unwrap(),
    );

    let results = pass_list
        .par_iter()
        .map(|pass| {
            bar.inc(1);

            // TODO: maybe support more hashes?
            let pass_hash = match query.trim().len() {
                32 => Some(format!("{:x}", Md5::digest(pass.as_bytes()))),
                40 => Some(format!("{:x}", Sha1::digest(pass.as_bytes()))),
                48 => Some(format!("{:x}", Tiger::digest(pass.as_bytes()))),
                56 => Some(format!("{:x}", Sha224::digest(pass.as_bytes()))),
                64 => Some(format!("{:x}", Sha256::digest(pass.as_bytes()))),
                96 => Some(format!("{:x}", Sha384::digest(pass.as_bytes()))),
                128 => Some(format!("{:x}", Sha512::digest(pass.as_bytes()))),
                _ => None,
            };

            if let Some(nice) = pass_hash {
                if nice == query {
                    println!("Some password has been here!");
                    return Some(pass.to_string());
                }
            }
            None
        })
        .collect::<Vec<Option<String>>>();

    results.into_iter().find_map(|x| x)
}
