use std::ops::Range;

pub(crate) const CRC32_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 == 1 {
                crc = 0xedb88320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc32_byte(crc: u32, byte: u8) -> u32 {
    CRC32_TABLE[((crc as u8) ^ byte) as usize] ^ (crc >> 8)
}

#[derive(Clone, Copy)]
pub(crate) struct PkwareKeys {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl PkwareKeys {
    fn initial() -> Self {
        PkwareKeys {
            k0: 0x12345678,
            k1: 0x23456789,
            k2: 0x34567890,
        }
    }

    /// Test-only convenience: derives the key state for a fresh password
    /// without the prefix cache.
    #[cfg(test)]
    fn new(password: &[u8]) -> Self {
        let mut k = Self::initial();
        for &b in password {
            k.update(b);
        }
        k
    }

    fn update(&mut self, plain: u8) {
        self.k0 = crc32_byte(self.k0, plain);
        self.k1 = self.k1.wrapping_add(self.k0 & 0xFF);
        self.k1 = self.k1.wrapping_mul(0x08088405).wrapping_add(1);
        self.k2 = crc32_byte(self.k2, (self.k1 >> 24) as u8);
    }

    fn decrypt_byte(&self) -> u8 {
        let temp = (self.k2 as u16) | 3;
        ((temp.wrapping_mul(temp ^ 1)) >> 8) as u8
    }

    fn decrypt(&mut self, cipher: u8) -> u8 {
        let plain = cipher ^ self.decrypt_byte();
        self.update(plain);
        plain
    }
}

/// Caches PKWARE key states so consecutive wordlist entries can resume from
/// their longest common prefix instead of replaying the whole password.
pub(crate) struct PkwareKeyCache {
    stack: Vec<(u8, PkwareKeys)>,
}

impl PkwareKeyCache {
    pub fn new() -> Self {
        Self {
            stack: Vec::with_capacity(64),
        }
    }

    /// Returns the key state for `password`.
    pub fn keys_for(&mut self, password: &[u8]) -> PkwareKeys {
        let mut common = 0;
        while common < self.stack.len()
            && common < password.len()
            && self.stack[common].0 == password[common]
        {
            common += 1;
        }
        self.stack.truncate(common);

        let mut keys = self
            .stack
            .last()
            .map(|&(_, keys)| keys)
            .unwrap_or_else(PkwareKeys::initial);
        for &byte in &password[common..] {
            keys.update(byte);
            self.stack.push((byte, keys));
        }
        keys
    }
}

pub(crate) struct ZipCryptoContext {
    pub enc_header: [u8; 12],
    /// Byte range of the encrypted payload within the archive buffer.
    pub payload: Range<usize>,
    pub check_byte: u8,
    pub stored_crc: u32,
    pub compression_method: u16,
}

#[cfg(test)]
pub(crate) fn verify_password_full(password: &[u8], ctx: &ZipCryptoContext, data: &[u8]) -> bool {
    verify_with_keys(PkwareKeys::new(password), ctx, data)
}

pub(crate) fn verify_with_keys(mut keys: PkwareKeys, ctx: &ZipCryptoContext, data: &[u8]) -> bool {
    // Phase 1: decrypt 12-byte header, check byte 11
    let mut buf = [0u8; 12];
    for (plain, &cipher) in buf.iter_mut().zip(ctx.enc_header.iter()) {
        *plain = keys.decrypt(cipher);
    }
    if buf[11] != ctx.check_byte {
        return false;
    }

    let payload = &data[ctx.payload.clone()];

    // Phase 2: decrypt the payload incrementally so the CRC can be updated in
    // the same pass. Only 1 in 256 wrong passwords reach this point; entries
    // whose deflate stream is corrupt are rejected after the first bytes
    // instead of decrypting and inflating the whole payload.
    match ctx.compression_method {
        0 => {
            let mut crc = 0xFFFFFFFFu32;
            for &cipher in payload {
                crc = crc32_byte(crc, keys.decrypt(cipher));
            }
            crc ^ 0xFFFFFFFF == ctx.stored_crc
        }
        8 | 9 => {
            use flate2::{Decompress, FlushDecompress, Status};

            let mut decomp = Decompress::new(false);
            let mut crc = 0xFFFFFFFFu32;
            let mut out = [0u8; 16384];
            let mut buf = [0u8; 4096];
            let mut pos = 0;

            while pos < payload.len() {
                let n = (payload.len() - pos).min(buf.len());
                for (plain, &cipher) in buf[..n].iter_mut().zip(&payload[pos..pos + n]) {
                    *plain = keys.decrypt(cipher);
                }
                pos += n;

                let mut input = &buf[..n];
                while !input.is_empty() {
                    let in_before = decomp.total_in();
                    let out_before = decomp.total_out();

                    match decomp.decompress(input, &mut out, FlushDecompress::None) {
                        Ok(Status::StreamEnd) => {
                            let produced = (decomp.total_out() - out_before) as usize;
                            for &byte in &out[..produced] {
                                crc = crc32_byte(crc, byte);
                            }
                            return crc ^ 0xFFFFFFFF == ctx.stored_crc;
                        }
                        Ok(_) => {}
                        Err(_) => return false,
                    }

                    let consumed = (decomp.total_in() - in_before) as usize;
                    let produced = (decomp.total_out() - out_before) as usize;
                    if consumed == 0 && produced == 0 {
                        return false;
                    }
                    for &byte in &out[..produced] {
                        crc = crc32_byte(crc, byte);
                    }
                    input = &input[consumed..];
                }
            }

            // The deflate stream ended prematurely.
            false
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_cache_matches_direct_derivation() {
        let mut cache = PkwareKeyCache::new();
        let passwords: &[&[u8]] = &[
            b"",
            b"a",
            b"ab",
            b"abc",
            b"abc",
            b"abx",
            b"abd",
            b"abc",
            b"z",
            b"abcdefghijklmnopqrstuvwxyz",
            b"abcdefghijklmnopqrstuvwxyza",
        ];
        for &password in passwords {
            let cached = cache.keys_for(password);
            let direct = PkwareKeys::new(password);
            assert_eq!(cached.k0, direct.k0);
            assert_eq!(cached.k1, direct.k1);
            assert_eq!(cached.k2, direct.k2);
        }
    }
}
