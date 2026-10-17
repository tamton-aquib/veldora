use crate::sha1mb::LANES;
use crate::util;
use crate::zip_aes::verify_passwords_aes;
use crate::zip_crypto::{verify_with_keys, verify_with_keys_pair, PkwareKeyCache};
use crate::zip_parser::{extract_zip_info, ZipEncryption};
use rayon::prelude::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub fn ettuz(
    filename: &str,
    pass_list: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    // The archive stays memory mapped; the contexts only hold byte ranges.
    let zip_data = util::map_file(filename)?;
    let encryption = match extract_zip_info(&zip_data) {
        Some(encryption) => encryption,
        None => {
            return Err(
                "Could not extract ZIP encryption info (unsupported or unencrypted archive)."
                    .into(),
            );
        }
    };

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

            // Per line bookkeeping: stop when another block found a password,
            // and advance the progress bar every 512 lines.
            macro_rules! tick {
                ($counter:expr, $end:expr) => {{
                    if $counter & 0x1FF == 0 {
                        if found_flag.load(Ordering::Relaxed) {
                            return None;
                        }
                        let delta = $end - reported;
                        let done = processed.fetch_add(delta, Ordering::Relaxed) + delta;
                        bar.set_position(done as u64);
                        reported = $end;
                    }
                }};
            }

            match &encryption {
                ZipEncryption::Traditional(ctx) => {
                    // Candidates are checked two at a time so the two key
                    // schedules overlap; each cache keeps its own prefix chain.
                    let mut cache_a = PkwareKeyCache::new();
                    let mut cache_b = PkwareKeyCache::new();
                    let mut first: Option<(usize, usize)> = None;
                    for (counter, (start, end)) in
                        wordlist.lines(block_start, block_end).enumerate()
                    {
                        tick!(counter, end);
                        let bytes = wordlist.bytes();
                        match first.take() {
                            None => first = Some((start, end)),
                            Some((start_a, end_a)) => {
                                let keys_a = cache_a.keys_for(&bytes[start_a..end_a]);
                                let keys_b = cache_b.keys_for(&bytes[start..end]);
                                let (hit_a, hit_b) =
                                    verify_with_keys_pair(keys_a, keys_b, ctx, &zip_data);
                                if hit_a {
                                    found_flag.store(true, Ordering::Relaxed);
                                    return Some((start_a, end_a));
                                }
                                if hit_b {
                                    found_flag.store(true, Ordering::Relaxed);
                                    return Some((start, end));
                                }
                            }
                        }
                    }

                    // Odd number of lines: check the last one alone.
                    if let Some((start, end)) = first {
                        let keys = cache_a.keys_for(&wordlist.bytes()[start..end]);
                        if verify_with_keys(keys, ctx, &zip_data) {
                            found_flag.store(true, Ordering::Relaxed);
                            return Some((start, end));
                        }
                    }
                }
                ZipEncryption::Aes(ctx) => {
                    let mut pending: [(usize, usize); LANES] = [(0, 0); LANES];
                    let mut pending_len = 0usize;
                    for (counter, (start, end)) in
                        wordlist.lines(block_start, block_end).enumerate()
                    {
                        tick!(counter, end);
                        pending[pending_len] = (start, end);
                        pending_len += 1;

                        if pending_len == LANES {
                            let bytes = wordlist.bytes();
                            let refs: [&[u8]; LANES] = std::array::from_fn(|lane| {
                                let (start, end) = pending[lane];
                                &bytes[start..end]
                            });
                            let hits = verify_passwords_aes(&refs, ctx, &zip_data);
                            if let Some(lane) = hits.iter().position(|&hit| hit) {
                                found_flag.store(true, Ordering::Relaxed);
                                return Some(pending[lane]);
                            }
                            pending_len = 0;
                        }
                    }

                    // Flush the last partial batch (padding slots never match
                    // in practice and are ignored when reading the flags).
                    if pending_len > 0 {
                        let bytes = wordlist.bytes();
                        let mut refs: [&[u8]; LANES] = [&[]; LANES];
                        for (lane, &(start, end)) in pending[..pending_len].iter().enumerate() {
                            refs[lane] = &bytes[start..end];
                        }
                        let hits = verify_passwords_aes(&refs, ctx, &zip_data);
                        if let Some(lane) = (0..pending_len).find(|&lane| hits[lane]) {
                            found_flag.store(true, Ordering::Relaxed);
                            return Some(pending[lane]);
                        }
                    }
                }
            }

            processed.fetch_add(block_end - reported, Ordering::Relaxed);
            None
        });

    bar.finish_and_clear();

    Ok(found.map(|(start, end)| wordlist.text(start, end).to_string()))
}
