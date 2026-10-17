use indicatif::{ProgressBar, ProgressStyle};
use memchr::memchr;
use memmap2::Mmap;
use std::fs::File;

/// Bounds for the line aligned blocks that are handed to rayon. The lower
/// bound avoids over-splitting small wordlists, the upper bound keeps the
/// work units small enough for good load balancing.
const MIN_BLOCK_SIZE: usize = 4 << 10;
const MAX_BLOCK_SIZE: usize = 4 << 20;

pub fn map_file(path: &str) -> Result<Mmap, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    // Both wordlists and archives are read front to back.
    let _ = mmap.advise(memmap2::Advice::Sequential);
    Ok(mmap)
}

/// A memory mapped wordlist split into line aligned blocks.
///
/// Block boundaries are found with a single memchr pass, so no per line offset
/// table is built: memory use stays flat and huge wordlists start instantly.
pub struct Wordlist {
    mmap: Mmap,
    block_starts: Vec<usize>,
}

impl Wordlist {
    pub fn open(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mmap = map_file(path)?;
        let block_starts = find_block_starts(&mmap, block_size(mmap.len()));
        Ok(Self { mmap, block_starts })
    }

    pub fn len(&self) -> usize {
        self.mmap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mmap.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.mmap
    }

    /// The candidate at the given byte range, or `"<binary>"` when it is not
    /// valid UTF-8.
    pub fn text(&self, start: usize, end: usize) -> &str {
        std::str::from_utf8(&self.mmap[start..end]).unwrap_or("<binary>")
    }

    pub fn num_blocks(&self) -> usize {
        self.block_starts.len()
    }

    /// Byte range of the line aligned block at `index`.
    pub fn block(&self, index: usize) -> (usize, usize) {
        let start = self.block_starts[index];
        let end = self
            .block_starts
            .get(index + 1)
            .copied()
            .unwrap_or(self.mmap.len());
        (start, end)
    }

    /// `(start, end)` byte offsets of the lines in a block.
    pub fn lines(&self, start: usize, end: usize) -> Lines<'_> {
        Lines {
            data: &self.mmap,
            pos: start,
            end,
        }
    }
}

pub struct Lines<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl Iterator for Lines<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<(usize, usize)> {
        if self.pos >= self.end {
            return None;
        }
        let start = self.pos;
        match memchr(b'\n', &self.data[self.pos..self.end]) {
            Some(offset) => {
                let newline = self.pos + offset;
                self.pos = newline + 1;
                let end = if newline > start && self.data[newline - 1] == b'\r' {
                    newline - 1
                } else {
                    newline
                };
                Some((start, end))
            }
            None => {
                // Final line without a trailing newline. The previous parser
                // did not trim a bare `\r` here, so keep that behavior.
                self.pos = self.end;
                Some((start, self.end))
            }
        }
    }
}

fn block_size(len: usize) -> usize {
    let threads = rayon::current_num_threads().max(1);
    (len / (threads * 8)).clamp(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE)
}

fn find_block_starts(data: &[u8], block_size: usize) -> Vec<usize> {
    if data.is_empty() {
        return Vec::new();
    }
    let mut starts = vec![0];
    let mut next = block_size;
    while next < data.len() {
        match memchr(b'\n', &data[next..]) {
            Some(offset) => {
                let after = next + offset + 1;
                if after >= data.len() {
                    break;
                }
                starts.push(after);
                next = after.saturating_add(block_size);
            }
            None => break,
        }
    }
    starts
}

pub fn make_progress_bar(total: u64) -> ProgressBar {
    let bar = ProgressBar::new(total);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] ({eta})")
            .unwrap(),
    );
    bar
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-line splitting behavior the module must preserve exactly.
    fn reference_lines(data: &[u8]) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        let mut start = 0;
        for (i, &b) in data.iter().enumerate() {
            if b == b'\n' {
                let end = if i > start && data[i - 1] == b'\r' {
                    i - 1
                } else {
                    i
                };
                out.push((start, end));
                start = i + 1;
            }
        }
        if start < data.len() {
            out.push((start, data.len()));
        }
        out
    }

    fn all_lines(data: &[u8], block_size: usize) -> Vec<(usize, usize)> {
        let starts = find_block_starts(data, block_size);
        let mut out = Vec::new();
        for (i, &start) in starts.iter().enumerate() {
            let end = starts.get(i + 1).copied().unwrap_or(data.len());
            out.extend(Lines {
                data,
                pos: start,
                end,
            });
        }
        out
    }

    #[test]
    fn block_splitting_matches_reference() {
        let mut data = Vec::new();
        for i in 0..500 {
            if i % 11 == 0 {
                data.extend_from_slice(b"\r\n");
            } else if i % 7 == 0 {
                data.push(b'\n');
            } else {
                data.extend_from_slice(format!("word{i}{i}").as_bytes());
                data.push(b'\n');
            }
        }
        data.extend_from_slice(b"tail");
        for block_size in [1, 7, 64, 4096] {
            assert_eq!(
                all_lines(&data, block_size),
                reference_lines(&data),
                "block size {block_size}"
            );
        }
    }

    #[test]
    fn block_boundaries_are_line_aligned() {
        let mut data = Vec::new();
        for _ in 0..100 {
            data.extend_from_slice(b"012345678\n");
        }
        let starts = find_block_starts(&data, 55);
        assert_eq!(starts[0], 0);
        for (i, &start) in starts.iter().enumerate().skip(1) {
            assert!(start > starts[i - 1], "blocks must be increasing");
            assert_eq!(data[start - 1], b'\n', "block {i} is not line aligned");
        }
        assert!(*starts.last().unwrap() < data.len() || starts.len() == 1);
    }

    #[test]
    fn no_newlines_yield_a_single_block() {
        assert_eq!(find_block_starts(b"no newlines here", 4), vec![0]);
        assert_eq!(find_block_starts(b"", 4), Vec::<usize>::new());
    }

    #[test]
    fn lines_skip_empty_trailing_line() {
        let data = b"a\n";
        let lines = Lines {
            data: &data[..],
            pos: 0,
            end: data.len(),
        };
        assert_eq!(lines.collect::<Vec<_>>(), vec![(0, 1)]);
    }
}
