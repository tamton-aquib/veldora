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
