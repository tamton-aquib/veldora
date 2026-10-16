use crate::pdf_crypto::PdfCryptoContext;
use crate::util;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub fn ettup(
    filename: &str,
    pass_file_name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let ctx = PdfCryptoContext::from_file(filename)?;

    let (mmap, lines) = util::mmap_wordlist(pass_file_name)?;
    let total = lines.len();

    if total == 0 {
        return Ok(None);
    }

    let bar = util::make_progress_bar(total as u64);

    let killed = AtomicBool::new(false);
    let processed = AtomicUsize::new(0);
    let found = lines.par_chunks(64).find_map_first(|chunk| {
        let done = processed.fetch_add(chunk.len(), Ordering::Relaxed) + chunk.len();
        bar.set_position(done as u64);

        for &(start, end) in chunk.iter() {
            if killed.load(Ordering::Relaxed) {
                return None;
            }
            if ctx.verify_password(&mmap[start..end]) {
                killed.store(true, Ordering::Relaxed);
                return Some((start, end));
            }
        }
        None
    });

    bar.finish_and_clear();

    match found {
        Some((start, end)) => {
            let pass = std::str::from_utf8(&mmap[start..end]).unwrap_or("<binary>");
            Ok(Some(pass.to_string()))
        }
        None => Ok(None),
    }
}
