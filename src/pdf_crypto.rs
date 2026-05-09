use pdf::backend::Backend;
use pdf::object::Resolve;
use pdf::primitive::{Dictionary, Primitive};

const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

pub struct PdfCryptoContext {
    pub o: [u8; 48],
    pub o_len: usize,
    pub u: [u8; 48],
    pub u_len: usize,
    pub id: [u8; 32],
    pub id_len: usize,
    pub p: i32,
    pub r: u32,
    pub v: i32,
    pub key_size: usize,
    pub encrypt_metadata: bool,
}

fn get_cf_length(dict: &Dictionary, res: &impl Resolve) -> Option<u32> {
    let cf = dict.get("CF")?;
    let cf_dict = cf.clone().into_dictionary(res).ok()?;
    let stdcf = cf_dict.get("StdCF")?;
    let stdcf_dict = stdcf.clone().into_dictionary(res).ok()?;
    let length = stdcf_dict.get("Length")?;
    length.as_integer().ok().map(|l| l as u32)
}

impl PdfCryptoContext {
    pub fn from_file(filename: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read(filename)?;
        let start_offset = data.locate_start_offset()?;
        let (refs, trailer) = data.read_xref_table_and_trailer(start_offset)?;
        let storage = pdf::file::Storage::new(data, refs, start_offset);

        let encrypt_primitive = trailer
            .get("Encrypt")
            .ok_or("PDF file is not encrypted")?
            .clone();

        let encrypt_dict = match encrypt_primitive {
            Primitive::Dictionary(d) => d,
            Primitive::Reference(r) => match storage.resolve(r)? {
                Primitive::Dictionary(d) => d,
                _ => return Err("Encrypt is not a dictionary".into()),
            },
            _ => return Err("Invalid Encrypt entry".into()),
        };

        let o_bytes = get_string_bytes(&encrypt_dict, "O")?;
        let u_bytes = get_string_bytes(&encrypt_dict, "U")?;
        let r_val = get_integer(&encrypt_dict, "R")? as u32;
        let p_val = get_integer(&encrypt_dict, "P")?;
        let v_val = get_integer(&encrypt_dict, "V")?;
        let encrypt_metadata = encrypt_dict
            .get("EncryptMetadata")
            .and_then(|p| p.as_bool().ok())
            .unwrap_or(true);

        let id = trailer
            .get("ID")
            .and_then(|p| p.as_array().ok())
            .and_then(|arr| arr.first())
            .and_then(|p| p.as_string().ok())
            .map(|s| s.data.clone())
            .unwrap_or_default();

        let key_bits = if v_val >= 4 {
            get_cf_length(&encrypt_dict, &storage)
                .map(|n| n * 8)
                .unwrap_or(128)
        } else if v_val == 2 {
            encrypt_dict
                .get("Length")
                .and_then(|len| len.as_integer().ok())
                .map(|len| len as u32)
                .unwrap_or(40)
        } else {
            40
        };

        let id_len = id.len().min(32);
        let o_len = o_bytes.len().min(48);
        let u_len = u_bytes.len().min(48);

        let mut ctx = Self {
            o: [0u8; 48],
            o_len,
            u: [0u8; 48],
            u_len,
            id: [0u8; 32],
            id_len,
            p: p_val,
            r: r_val,
            v: v_val,
            key_size: (key_bits / 8) as usize,
            encrypt_metadata,
        };
        ctx.o[..o_len].copy_from_slice(&o_bytes[..o_len]);
        ctx.u[..u_len].copy_from_slice(&u_bytes[..u_len]);
        ctx.id[..id_len].copy_from_slice(&id[..id_len]);
        Ok(ctx)
    }

    pub fn verify_password(&self, pass: &[u8]) -> bool {
        match self.r {
            2 => self.verify_r2(pass),
            3 | 4 => self.verify_r34(pass),
            _ => false,
        }
    }

    fn verify_r2(&self, pass: &[u8]) -> bool {
        let key = derive_key_user(pass, self);
        let mut u_computed = PADDING;
        rc4_encrypt(&key[..self.key_size], &mut u_computed);
        &u_computed[..self.u_len] == &self.u[..self.u_len]
    }

    fn verify_r34(&self, pass: &[u8]) -> bool {
        let key = derive_key_user(pass, self);
        let u_computed = compute_u_rev_3_4(&self.id[..self.id_len], &key[..self.key_size]);
        if &u_computed == &self.u[..16] {
            return true;
        }

        let owner_key = derive_key_owner(pass, self);
        let mut decrypted_o = [0u8; 48];
        decrypted_o[..self.o_len].copy_from_slice(&self.o[..self.o_len]);
        rc4_encrypt(&owner_key[..self.key_size], &mut decrypted_o[..self.o_len]);
        for i in 1u8..=19 {
            let mut round_key = [0u8; 16];
            round_key[..self.key_size].copy_from_slice(&owner_key[..self.key_size]);
            for b in &mut round_key[..self.key_size] {
                *b ^= i;
            }
            rc4_encrypt(&round_key[..self.key_size], &mut decrypted_o[..self.o_len]);
        }

        let user_pass = &decrypted_o[..32];
        let user_key = derive_key_user(user_pass, self);
        let u_computed2 = compute_u_rev_3_4(&self.id[..self.id_len], &user_key[..self.key_size]);
        &u_computed2 == &self.u[..16]
    }

}

fn derive_key_user_init(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
    let mut buf = [0u8; 128];
    let mut len = 0;

    let pass_len = pass.len().min(32);
    buf[..pass_len].copy_from_slice(&pass[..pass_len]);
    len += pass_len;
    if pass_len < 32 {
        buf[len..len + 32 - pass_len].copy_from_slice(&PADDING[..32 - pass_len]);
        len += 32 - pass_len;
    }

    buf[len..len + ctx.o_len].copy_from_slice(&ctx.o[..ctx.o_len]);
    len += ctx.o_len;

    buf[len..len + 4].copy_from_slice(&ctx.p.to_le_bytes());
    len += 4;

    buf[len..len + ctx.id_len].copy_from_slice(&ctx.id[..ctx.id_len]);
    len += ctx.id_len;

    if ctx.r >= 4 && !ctx.encrypt_metadata {
        buf[len..len + 4].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        len += 4;
    }

    md5_once(&buf[..len])
}

// ── Inline MD5 compression (no FFI, no dependencies) ──

const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const MD5_S: [u32; 64] = [
     7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
     5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
     4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
     6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,
];

const MD5_W: [usize; 64] = [
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
     1,  6, 11,  0,  5, 10, 15,  4,  9, 14,  3,  8, 13,  2,  7, 12,
     5,  8, 11, 14,  1,  4,  7, 10, 13,  0,  3,  6,  9, 12, 15,  2,
     0,  7, 14,  5, 12,  3, 10,  1,  8, 15,  6, 13,  4, 11,  2,  9,
];

#[inline(always)]
fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]) {
    let [mut a, mut b, mut c, mut d] = *state;
    let (sa, sb, sc, sd) = (a, b, c, d);

    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3],
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
        let t = val.wrapping_add(f)
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
fn md5_once(data: &[u8]) -> [u8; 16] {
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

fn md5_round_50(hash: &[u8; 16], key_size: usize) -> [u8; 16] {
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

fn derive_key_user(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
    let mut hash = derive_key_user_init(pass, ctx);
    if ctx.r >= 3 {
        hash = md5_round_50(&hash, ctx.key_size);
    }
    hash
}

fn derive_key_owner(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
    let mut buf = [0u8; 64];
    let mut len = 0;

    let pass_len = pass.len().min(32);
    buf[..pass_len].copy_from_slice(&pass[..pass_len]);
    len += pass_len;
    if pass_len < 32 {
        buf[len..len + 32 - pass_len].copy_from_slice(&PADDING[..32 - pass_len]);
        len += 32 - pass_len;
    }

    let mut hash = md5_once(&buf[..len]);
    if ctx.r >= 3 {
        hash = md5_round_50(&hash, ctx.key_size);
    }
    hash
}

fn compute_u_rev_3_4(id: &[u8], key: &[u8]) -> [u8; 16] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&PADDING);
    buf[32..32 + id.len()].copy_from_slice(id);

    let mut data = md5_once(&buf[..32 + id.len()]);
    rc4_encrypt(key, &mut data);

    for i in 1u8..=19 {
        let mut round_key = [0u8; 16];
        round_key[..key.len()].copy_from_slice(key);
        for b in &mut round_key[..key.len()] {
            *b ^= i;
        }
        rc4_encrypt(&round_key[..key.len()], &mut data);
    }

    data
}

#[inline(always)]
fn rc4_encrypt(key: &[u8], data: &mut [u8]) {
    let mut state = [0u8; 256];
    for i in 0..256 {
        state[i] = i as u8;
    }
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }

    let mut i: u8 = 0;
    let mut j: u8 = 0;
    for b in data.iter_mut() {
        i = i.wrapping_add(1);
        j = j.wrapping_add(state[i as usize]);
        state.swap(i as usize, j as usize);
        let k = state[(state[i as usize].wrapping_add(state[j as usize])) as usize];
        *b ^= k;
    }
}

fn get_string_bytes(dict: &Dictionary, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(dict
        .get(key)
        .ok_or_else(|| format!("Missing /{} in Encrypt dictionary", key))?
        .as_string()
        .map_err(|_| format!("Invalid /{} in Encrypt dictionary", key))?
        .data
        .clone())
}

fn get_integer(dict: &Dictionary, key: &str) -> Result<i32, Box<dyn std::error::Error>> {
    Ok(dict
        .get(key)
        .ok_or_else(|| format!("Missing /{} in Encrypt dictionary", key))?
        .as_integer()
        .map_err(|_| format!("Invalid /{} in Encrypt dictionary", key))?)
}
