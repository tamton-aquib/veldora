use std::convert::TryInto;
use sha2::{Digest, Sha256, Sha384, Sha512};
use crate::pdf_crypto::md5::{md5_once, md5_round_50};
use crate::pdf_crypto::rc4::rc4_encrypt;
use crate::pdf_crypto::aes::aes_128_cbc_encrypt;
use crate::pdf_crypto::parser::PdfCryptoContext;

pub(crate) const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41,
    0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80,
    0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

pub(crate) fn derive_key_user_init(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
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

pub(crate) fn derive_key_user(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
    let mut hash = derive_key_user_init(pass, ctx);
    if ctx.r >= 3 {
        hash = md5_round_50(&hash, ctx.key_size);
    }
    hash
}

pub(crate) fn derive_key_owner(pass: &[u8], ctx: &PdfCryptoContext) -> [u8; 16] {
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

pub(crate) fn compute_u_rev_3_4(id: &[u8], key: &[u8]) -> [u8; 16] {
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

pub(crate) fn hash_v5(password: &[u8], salt: &[u8; 8], udata: &[u8], r: u32) -> [u8; 32] {
    if r == 5 {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(udata);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        return out;
    }

    let mut k = {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(udata);
        let result = hasher.finalize();
        result.to_vec()
    };

    for round_num in 1.. {
        let k1: Vec<u8> = [password, &k, udata].concat();
        let data: Vec<u8> = k1.repeat(64);

        let aes_key: &[u8; 16] = (&k[0..16]).try_into().unwrap();
        let aes_iv: &[u8; 16] = (&k[16..32]).try_into().unwrap();

        let e = aes_128_cbc_encrypt(aes_key, aes_iv, &data);

        let sum_first16: u32 = e.iter().take(16).map(|&b| b as u32).sum();
        let hash_bits = match sum_first16 % 3 {
            0 => 256,
            1 => 384,
            _ => 512,
        };

        k = match hash_bits {
            256 => {
                let mut hasher = Sha256::new();
                hasher.update(&e);
                hasher.finalize().to_vec()
            }
            384 => {
                let mut hasher = Sha384::new();
                hasher.update(&e);
                hasher.finalize().to_vec()
            }
            _ => {
                let mut hasher = Sha512::new();
                hasher.update(&e);
                hasher.finalize().to_vec()
            }
        };

        if round_num >= 64 {
            let last_byte = e.last().copied().unwrap_or(0);
            if (last_byte as u32) <= (round_num - 32) {
                break;
            }
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&k[..32]);
    out
}
