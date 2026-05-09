use indicatif::{ProgressBar, ProgressStyle};
use memmap2::Mmap;
use std::fs::File;

pub fn collect_line_offsets(data: &[u8]) -> Vec<(usize, usize)> {
    let mut offsets = Vec::new();
    let mut start = 0;
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            let end = if i > 0 && data[i - 1] == b'\r' {
                i - 1
            } else {
                i
            };
            offsets.push((start, end));
            start = i + 1;
        }
    }
    if start < data.len() {
        offsets.push((start, data.len()));
    }
    offsets
}

pub fn mmap_wordlist(
    path: &str,
) -> Result<(Mmap, Vec<(usize, usize)>), Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let mmap = unsafe { Mmap::map(&file)? };
    let lines = collect_line_offsets(&mmap);
    Ok((mmap, lines))
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
