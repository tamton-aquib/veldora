//! # Hash bruteforcing module
//!
//! For bruteforcing popular hashes. Will add more hashtypes soon.

use indicatif::{ProgressBar, ProgressStyle};
use md5::{Digest, Md5};
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::fs::File;
use std::io::{BufRead, BufReader};
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
    let target_hex = query.trim();
    let target: Vec<u8> = (0..target_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&target_hex[i..i + 2], 16).unwrap())
        .collect();

    let reader = BufReader::new(
        File::open(pass_list).expect("Error reading the file. Make sure its UTF-8 encoded!"),
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
            match target.len() {
                16 => &*Md5::digest(pass.as_bytes()) == target.as_slice(),
                20 => &*Sha1::digest(pass.as_bytes()) == target.as_slice(),
                24 => &*Tiger::digest(pass.as_bytes()) == target.as_slice(),
                28 => &*Sha224::digest(pass.as_bytes()) == target.as_slice(),
                32 => &*Sha256::digest(pass.as_bytes()) == target.as_slice(),
                48 => &*Sha384::digest(pass.as_bytes()) == target.as_slice(),
                64 => &*Sha512::digest(pass.as_bytes()) == target.as_slice(),
                _ => false,
            }
        })
        .map(|pass| pass.to_string())
}
