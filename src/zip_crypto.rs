use std::io::Read;

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

struct PkwareKeys {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl PkwareKeys {
    fn new(password: &[u8]) -> Self {
        let mut k = PkwareKeys {
            k0: 0x12345678,
            k1: 0x23456789,
            k2: 0x34567890,
        };
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

pub(crate) struct ZipCryptoContext {
    pub enc_header: [u8; 12],
    pub encrypted_payload: Vec<u8>,
    pub check_byte: u8,
    pub stored_crc: u32,
    pub compression_method: u16,
}

pub(crate) fn verify_password_full(password: &[u8], ctx: &ZipCryptoContext) -> bool {
    use flate2::read::DeflateDecoder;

    let mut keys = PkwareKeys::new(password);

    // Phase 1: decrypt 12-byte header, check byte 11
    let mut buf = [0u8; 12];
    for (plain, &cipher) in buf.iter_mut().zip(ctx.enc_header.iter()) {
        *plain = keys.decrypt(cipher);
    }
    if buf[11] != ctx.check_byte {
        return false;
    }

    // Phase 2: decrypt payload
    let mut decrypted = Vec::with_capacity(ctx.encrypted_payload.len());
    for &b in &ctx.encrypted_payload {
        decrypted.push(keys.decrypt(b));
    }

    // Phase 3: decompress (if needed) and CRC check
    let data_for_crc = match ctx.compression_method {
        0 => decrypted,
        8 | 9 => {
            let mut decompressed = Vec::new();
            let mut decoder = DeflateDecoder::new(&decrypted[..]);
            if decoder.read_to_end(&mut decompressed).is_err() {
                return false;
            }
            decompressed
        }
        _ => return false,
    };

    let mut crc = 0xFFFFFFFFu32;
    for &b in &data_for_crc {
        crc = CRC32_TABLE[((crc as u8) ^ b) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF == ctx.stored_crc
}
