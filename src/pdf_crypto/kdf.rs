use crate::pdf_crypto::md5::{md5_once, md5_round_50};
use crate::pdf_crypto::parser::PdfCryptoContext;
use crate::pdf_crypto::rc4::rc4_encrypt;
use aes::cipher::{consts::U16, generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use sha2::{Digest, Sha256, Sha384, Sha512};

pub(crate) const PADDING: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
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
        // Algorithm 3.3 hashes the full 16-byte output each round; only the
        // resulting key is later truncated to the key size.
        hash = md5_round_50(&hash, 16);
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

/// Maximum size of the round key K (a SHA-512 digest).
const K_MAX: usize = 64;

/// Selects and drives the digest used for one round of Algorithm 2.B.
enum RoundHasher {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl RoundHasher {
    fn new(selector: u32) -> Self {
        match selector % 3 {
            0 => Self::Sha256(Sha256::new()),
            1 => Self::Sha384(Sha384::new()),
            _ => Self::Sha512(Sha512::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hasher) => hasher.update(data),
            Self::Sha384(hasher) => hasher.update(data),
            Self::Sha512(hasher) => hasher.update(data),
        }
    }

    /// Writes the digest into `out` and returns its length.
    fn finalize_into(self, out: &mut [u8; K_MAX]) -> usize {
        match self {
            Self::Sha256(hasher) => {
                out[..32].copy_from_slice(&hasher.finalize());
                32
            }
            Self::Sha384(hasher) => {
                out[..48].copy_from_slice(&hasher.finalize());
                48
            }
            Self::Sha512(hasher) => {
                out[..64].copy_from_slice(&hasher.finalize());
                64
            }
        }
    }
}

pub(crate) fn hash_v5(password: &[u8], salt: &[u8; 8], udata: &[u8], r: u32) -> [u8; 32] {
    // ISO 32000-2 truncates the password to 127 bytes before hashing.
    let password = &password[..password.len().min(127)];

    if r == 5 {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(udata);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        return out;
    }

    // K = SHA-256(password || salt || udata); it is replaced by a 32, 48 or
    // 64 byte digest every round.
    let mut k = [0u8; K_MAX];
    let mut k_len = 32;
    {
        let mut hasher = Sha256::new();
        hasher.update(password);
        hasher.update(salt);
        hasher.update(udata);
        k[..32].copy_from_slice(&hasher.finalize());
    }

    // Reused buffers: allocated once per call so the round loop is
    // allocation free. K1 = password || K || udata, E holds K1 repeated 64
    // times as it is encrypted.
    let password_len = password.len();
    let mut k1 = [0u8; 127 + K_MAX + 48];
    k1[..password_len].copy_from_slice(password);
    let mut e = vec![0u8; 64 * (password_len + K_MAX + udata.len())];

    for round_num in 1u32.. {
        let key: [u8; 16] = k[..16].try_into().unwrap();
        let iv: [u8; 16] = k[16..32].try_into().unwrap();

        k1[password_len..password_len + k_len].copy_from_slice(&k[..k_len]);
        let udata_offset = password_len + k_len;
        let k1_len = udata_offset + udata.len();
        k1[udata_offset..k1_len].copy_from_slice(udata);

        // E = AES-128-CBC(key, iv, K1 repeated 64 times).
        let total = 64 * k1_len;
        for chunk in e[..total].chunks_mut(k1_len) {
            chunk.copy_from_slice(&k1[..k1_len]);
        }

        let cipher = Aes128::new_from_slice(&key).unwrap();
        let mut prev: GenericArray<u8, U16> = GenericArray::clone_from_slice(&iv);
        for chunk in e[..total].as_chunks_mut::<16>().0 {
            for (b, p) in chunk.iter_mut().zip(prev.iter()) {
                *b ^= p;
            }
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
            prev.copy_from_slice(chunk);
        }
        debug_assert_eq!(total % 16, 0); // 64 repetitions always end on a block boundary

        let sum: u32 = e[..16].iter().map(|&b| b as u32).sum();
        let last_byte = e[total - 1];

        let mut hasher = RoundHasher::new(sum);
        hasher.update(&e[..total]);
        k_len = hasher.finalize_into(&mut k);

        if round_num >= 64 && last_byte as u32 <= round_num - 32 {
            break;
        }
    }

    let mut out = [0u8; 32];
    out.copy_from_slice(&k[..32]);
    out
}
