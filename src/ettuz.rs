use crate::util;
use crate::zip_aes::verify_password_aes;
use crate::zip_crypto::verify_password_full;
use crate::zip_parser::{extract_zip_info, ZipEncryption};
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};

pub fn ettuz(
    filename: &str,
    pass_list: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // Pre-extract ZIP data once — zero I/O during cracking
    let zip_data = std::fs::read(filename)?;
    let encryption = match extract_zip_info(&zip_data) {
        Some(encryption) => encryption,
        None => {
            return Err(
                "Could not extract ZIP encryption info (unsupported or unencrypted archive)."
                    .into(),
            );
        }
    };
    drop(zip_data);

    // mmap wordlist — zero-copy line access
    let (mmap, lines) = util::mmap_wordlist(pass_list)?;
    let total = lines.len();

    let bar = util::make_progress_bar(total as u64);

    let processed = AtomicUsize::new(0);
    let found = lines.par_iter().find_first(|&&(start, end)| {
        let p = processed.fetch_add(1, Ordering::Relaxed);
        if p & 0x1FF == 0 {
            // update every ~512 passwords
            bar.set_position(p as u64);
        }
        let pass = &mmap[start..end];
        match &encryption {
            ZipEncryption::Traditional(ctx) => verify_password_full(pass, ctx),
            ZipEncryption::Aes(ctx) => verify_password_aes(pass, ctx),
        }
    });

    bar.finish_and_clear();

    Ok(match found {
        Some(&(start, end)) => {
            let pass = std::str::from_utf8(&mmap[start..end]).unwrap_or("<binary>");
            Some(pass.to_string())
        }
        None => None,
    })
}
