use crate::pdf_crypto::PdfCryptoContext;
use crate::util;
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub fn ettup(
    filename: &str,
    pass_file_name: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let ctx = PdfCryptoContext::from_file(filename)?;

    let wordlist = util::Wordlist::open(pass_file_name)?;
    if wordlist.is_empty() {
        return Ok(None);
    }

    let bar = util::make_progress_bar(wordlist.len() as u64);

    let killed = AtomicBool::new(false);
    let processed = AtomicUsize::new(0);
    let found = (0..wordlist.num_blocks())
        .into_par_iter()
        .find_map_first(|block_index| {
            let (block_start, block_end) = wordlist.block(block_index);
            let mut reported = block_start;

            for (counter, (start, end)) in wordlist.lines(block_start, block_end).enumerate() {
                if killed.load(Ordering::Relaxed) {
                    return None;
                }
                if counter & 0x1FF == 0 {
                    let delta = end - reported;
                    let done = processed.fetch_add(delta, Ordering::Relaxed) + delta;
                    bar.set_position(done as u64);
                    reported = end;
                }

                if ctx.verify_password(&wordlist.bytes()[start..end]) {
                    killed.store(true, Ordering::Relaxed);
                    return Some((start, end));
                }
            }
            processed.fetch_add(block_end - reported, Ordering::Relaxed);
            None
        });

    bar.finish_and_clear();

    match found {
        Some((start, end)) => Ok(Some(wordlist.text(start, end).to_string())),
        None => Ok(None),
    }
}
