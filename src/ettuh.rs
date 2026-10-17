//! # Hash bruteforcing module
//!
//! For bruteforcing popular hashes. Will add more hashtypes soon.

use crate::util;
use md5::{Digest, Md5};
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tiger::Tiger;

/// Bruteforces the password for hashes like md5, Sha512, etc.
///
/// # Examples
///
/// ```no_run
/// use veldora::ettuh::ettuh;
///
/// // ... rest of your code.
/// match ettuh("5d41402abc4b2a76b9719d911017c592", "/path/to/passlist.txt") {
///     Ok(Some(pass)) => println!("Possible password: {}", pass),
///     Ok(None) => println!("Couldn't get password!"),
///     Err(e) => eprintln!("{}", e),
/// };
/// ```
pub fn ettuh(query: &str, pass_list: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let target = parse_hash(query)?;

    let wordlist = util::Wordlist::open(pass_list)?;
    if wordlist.is_empty() {
        return Ok(None);
    }

    let bar = util::make_progress_bar(wordlist.len() as u64);
    let found_flag = AtomicBool::new(false);
    let processed = AtomicUsize::new(0);

    let found = (0..wordlist.num_blocks())
        .into_par_iter()
        .find_map_first(|block_index| {
            let (block_start, block_end) = wordlist.block(block_index);
            let mut reported = block_start;

            for (counter, (start, end)) in wordlist.lines(block_start, block_end).enumerate() {
                // Check for a match in another block every 512 lines so the
                // remaining candidates are not paid for.
                if counter & 0x1FF == 0 {
                    if found_flag.load(Ordering::Relaxed) {
                        return None;
                    }
                    let delta = end - reported;
                    let done = processed.fetch_add(delta, Ordering::Relaxed) + delta;
                    bar.set_position(done as u64);
                    reported = end;
                }

                let pass = &wordlist.bytes()[start..end];
                let matched = match target.len() {
                    16 => Md5::digest(pass).as_slice() == target.as_slice(),
                    20 => Sha1::digest(pass).as_slice() == target.as_slice(),
                    24 => Tiger::digest(pass).as_slice() == target.as_slice(),
                    28 => Sha224::digest(pass).as_slice() == target.as_slice(),
                    32 => Sha256::digest(pass).as_slice() == target.as_slice(),
                    48 => Sha384::digest(pass).as_slice() == target.as_slice(),
                    _ => Sha512::digest(pass).as_slice() == target.as_slice(),
                };
                if matched {
                    found_flag.store(true, Ordering::Relaxed);
                    return Some((start, end));
                }
            }
            processed.fetch_add(block_end - reported, Ordering::Relaxed);
            None
        });

    bar.finish_and_clear();

    Ok(found.map(|(start, end)| wordlist.text(start, end).to_string()))
}

fn parse_hash(query: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let hex = query.trim();
    if !hex.len().is_multiple_of(2) {
        return Err(format!(
            "Invalid hash: '{}' has an odd number of hex characters",
            query
        )
        .into());
    }

    let target: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<_, _>>()
        .map_err(|_| format!("Invalid hash: '{}' is not valid hexadecimal", query))?;

    match target.len() {
        16 | 20 | 24 | 28 | 32 | 48 | 64 => Ok(target),
        n => Err(format!(
            "Unsupported hash length: {} bytes (expected 16, 20, 24, 28, 32, 48 or 64)",
            n
        )
        .into()),
    }
}
