pub(crate) const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

pub(crate) const MD5_S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

pub(crate) const MD5_W: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8,
    13, 2, 7, 12, 5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, 0, 7, 14, 5, 12, 3, 10, 1,
    8, 15, 6, 13, 4, 11, 2, 9,
];

#[inline(always)]
pub(crate) fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let [mut a, mut b, mut c, mut d] = *state;
    let (sa, sb, sc, sd) = (a, b, c, d);

    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }

    for step in 0..64 {
        let g = MD5_W[step];
        let (f, val, add) = match step >> 4 {
            0 => match step & 3 {
                0 => ((b & c) | (!b & d), a, b),
                1 => ((a & b) | (!a & c), d, a),
                2 => ((d & a) | (!d & b), c, d),
                _ => ((c & d) | (!c & a), b, c),
            },
            1 => match step & 3 {
                0 => ((b & d) | (c & !d), a, b),
                1 => ((a & c) | (b & !c), d, a),
                2 => ((d & b) | (a & !b), c, d),
                _ => ((c & a) | (d & !a), b, c),
            },
            2 => match step & 3 {
                0 => (b ^ c ^ d, a, b),
                1 => (a ^ b ^ c, d, a),
                2 => (d ^ a ^ b, c, d),
                _ => (c ^ d ^ a, b, c),
            },
            _ => match step & 3 {
                0 => (c ^ (b | !d), a, b),
                1 => (b ^ (a | !c), d, a),
                2 => (a ^ (d | !b), c, d),
                _ => (d ^ (c | !a), b, c),
            },
        };
        let t = val
            .wrapping_add(f)
            .wrapping_add(x[g])
            .wrapping_add(MD5_T[step])
            .rotate_left(MD5_S[step])
            .wrapping_add(add);
        match step & 3 {
            0 => a = t,
            1 => d = t,
            2 => c = t,
            _ => b = t,
        }
    }

    state[0] = sa.wrapping_add(a);
    state[1] = sb.wrapping_add(b);
    state[2] = sc.wrapping_add(c);
    state[3] = sd.wrapping_add(d);
}

#[inline(always)]
pub(crate) fn md5_once(data: &[u8]) -> [u8; 16] {
    let mut state = [0x67452301u32, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
    let mut block = [0u8; 64];
    let mut offset = 0;

    while offset + 64 <= data.len() {
        block.copy_from_slice(&data[offset..offset + 64]);
        md5_compress(&mut state, &block);
        offset += 64;
    }

    let remaining = data.len() - offset;
    block.fill(0);
    block[..remaining].copy_from_slice(&data[offset..]);
    block[remaining] = 0x80;

    if remaining >= 55 {
        md5_compress(&mut state, &block);
        block.fill(0);
    }

    let bit_len = (data.len() as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_le_bytes());
    md5_compress(&mut state, &block);

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&state[0].to_le_bytes());
    out[4..8].copy_from_slice(&state[1].to_le_bytes());
    out[8..12].copy_from_slice(&state[2].to_le_bytes());
    out[12..16].copy_from_slice(&state[3].to_le_bytes());
    out
}

pub(crate) fn md5_round_50(hash: &[u8; 16], key_size: usize) -> [u8; 16] {
    let mut block = [0u8; 64];
    block[key_size] = 0x80;
    let bit_len = (key_size as u64) * 8;
    block[56..64].copy_from_slice(&bit_len.to_le_bytes());

    let mut h = *hash;
    for _ in 0..50 {
        block[..key_size].copy_from_slice(&h[..key_size]);
        let mut state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
        md5_compress(&mut state, &block);
        h[..4].copy_from_slice(&state[0].to_le_bytes());
        h[4..8].copy_from_slice(&state[1].to_le_bytes());
        h[8..12].copy_from_slice(&state[2].to_le_bytes());
        h[12..16].copy_from_slice(&state[3].to_le_bytes());
    }
    h
}
