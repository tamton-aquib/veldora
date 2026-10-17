use crate::sha1mb::{compress, compress_tail, tail_block, LANES};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use std::ops::Range;

/// Everything needed to check passwords of a WinZip AES (AE-1/AE-2) entry.
pub(crate) struct AesContext {
    pub salt: Vec<u8>,
    pub verifier: [u8; 2],
    pub auth_code: [u8; 10],
    /// Byte range of the encrypted data within the archive buffer.
    pub ciphertext: Range<usize>,
    pub key_len: usize,
}

/// Fixed by the WinZip AES specification (AE-1/AE-2).
const PBKDF2_ROUNDS: u32 = 1000;

const SHA1_IV: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// Checks `LANES` passwords at once; the returned flags are per input slot.
///
/// The PBKDF2 chains of the candidates are independent, so they are advanced
/// in lockstep through the four-way SHA-1 compression function.
pub(crate) fn verify_passwords_aes(
    passwords: &[&[u8]; LANES],
    ctx: &AesContext,
    data: &[u8],
) -> [bool; LANES] {
    let dk_len = 2 * ctx.key_len + 2;

    // HMAC-SHA1 pad midstates, two compressions per candidate.
    let mut ipad_states = [SHA1_IV; LANES];
    let mut opad_states = [SHA1_IV; LANES];
    let mut ipad_blocks = [[0u8; 64]; LANES];
    let mut opad_blocks = [[0u8; 64]; LANES];
    for lane in 0..LANES {
        let key = normalize_hmac_key(passwords[lane]);
        for i in 0..64 {
            ipad_blocks[lane][i] = key[i] ^ 0x36;
            opad_blocks[lane][i] = key[i] ^ 0x5c;
        }
    }
    compress(&mut ipad_states, &ipad_blocks);
    compress(&mut opad_states, &opad_blocks);

    // PBKDF2-HMAC-SHA1, all candidates in lockstep.
    let mut derived = [[0u8; 2 * 32 + 2]; LANES];
    let block_count = dk_len.div_ceil(20);
    for block_index in 0..block_count {
        let mut seed_blocks = [[0u8; 64]; LANES];
        for seed in seed_blocks.iter_mut() {
            let mut message = [0u8; 20];
            message[..ctx.salt.len()].copy_from_slice(&ctx.salt);
            message[ctx.salt.len()..ctx.salt.len() + 4]
                .copy_from_slice(&(block_index as u32 + 1).to_be_bytes());
            *seed = tail_block(&message[..ctx.salt.len() + 4]);
        }

        let mut u = {
            let inner = compress_blocks(&ipad_states, &seed_blocks);
            compress_digests(&opad_states, &inner)
        };
        let mut acc = u;

        for _ in 1..PBKDF2_ROUNDS {
            let inner = compress_digests(&ipad_states, &u);
            u = compress_digests(&opad_states, &inner);
            for lane in 0..LANES {
                for (a, b) in acc[lane].iter_mut().zip(u[lane].iter()) {
                    *a ^= b;
                }
            }
        }

        let start = block_index * 20;
        let n = (dk_len - start).min(20);
        for lane in 0..LANES {
            derived[lane][start..start + n].copy_from_slice(&acc[lane][..n]);
        }
    }

    let mut results = [false; LANES];
    for (lane, result) in results.iter_mut().enumerate() {
        let dk = &derived[lane][..dk_len];
        if dk[2 * ctx.key_len..] == ctx.verifier {
            *result = confirm_mac(&dk[ctx.key_len..2 * ctx.key_len], ctx, data);
        }
    }
    results
}

/// HMAC key normalization: keys longer than the block size are hashed first.
fn normalize_hmac_key(password: &[u8]) -> [u8; 64] {
    let mut key = [0u8; 64];
    if password.len() > 64 {
        key[..20].copy_from_slice(&Sha1::digest(password));
    } else {
        key[..password.len()].copy_from_slice(password);
    }
    key
}

/// Compresses one prepared block per lane and returns the digests.
#[inline]
fn compress_blocks(states: &[[u32; 5]; LANES], blocks: &[[u8; 64]; LANES]) -> [[u8; 20]; LANES] {
    let mut states = *states;
    compress(&mut states, blocks);
    state_digests(&states)
}

/// Compresses one 20 byte message per lane and returns the digests.
#[inline]
fn compress_digests(states: &[[u32; 5]; LANES], digests: &[[u8; 20]; LANES]) -> [[u8; 20]; LANES] {
    let mut states = *states;
    compress_tail(&mut states, digests);
    state_digests(&states)
}

#[inline]
fn state_digests(states: &[[u32; 5]; LANES]) -> [[u8; 20]; LANES] {
    let mut digests = [[0u8; 20]; LANES];
    for (digest, state) in digests.iter_mut().zip(states.iter()) {
        for (chunk, word) in digest.chunks_mut(4).zip(state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
    }
    digests
}

/// Confirms a verifier hit against the truncated HMAC-SHA1 auth code.
fn confirm_mac(mac_key: &[u8], ctx: &AesContext, data: &[u8]) -> bool {
    let mut mac = Hmac::<Sha1>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&data[ctx.ciphertext.clone()]);
    mac.finalize().into_bytes()[..10] == ctx.auth_code
}

/// Single-candidate reference implementation, used by the tests to check the
/// batched path against a well known crate.
#[cfg(test)]
pub(crate) fn verify_password_aes(password: &[u8], ctx: &AesContext, data: &[u8]) -> bool {
    let mut derived = [0u8; 2 * 32 + 2];
    let dk_len = 2 * ctx.key_len + 2;
    pbkdf2::pbkdf2_hmac::<Sha1>(password, &ctx.salt, PBKDF2_ROUNDS, &mut derived[..dk_len]);

    let mac_key = &derived[ctx.key_len..2 * ctx.key_len];
    if derived[2 * ctx.key_len..dk_len] != ctx.verifier {
        return false;
    }
    confirm_mac(mac_key, ctx, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip_crypto::{verify_password_full, verify_with_keys_pair, PkwareKeys};
    use crate::zip_parser::{extract_zip_info, ZipEncryption};

    fn decode_hex(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // Generated with 7-Zip (AES-256, ZipCrypto) and a hand-rolled WinZip AES
    // writer (AES-128 with the bit-6 strong encryption flag, AES-192 without);
    // all four were validated against `7z t -psecret` before being embedded.
    const AES128_ZIP: &str = concat!(
        "504b030433004100630000002158000000002b0000001500000007000b006165732e74787401990700020041450108003132333435363738",
        "6fabc858355dcd87c00c778eff2aea2c509b518614c716018ce11c3302a09be590867a504b01023f0333004100630000002158000000002b",
        "0000001500000007000b0000000000000000000000000000006165732e7478740199070002004145010800504b0506000000000100010040",
        "0000005b0000000000",
    );

    const AES192_ZIP: &str = concat!(
        "504b030433000100630000002158000000002f000000150000000a000b006165733139322e74787401990700020041450208003132333435",
        "363738393a3b3c4bc000cef0d2df28b527ae7338e045b704b96cd483efb93415025fc2cfca5f883af0ad504b01023f033300010063000000",
        "2158000000002f000000150000000a000b0000000000000000000000000000006165733139322e7478740199070002004145020800504b05",
        "06000000000100010043000000620000000000",
    );

    const AES256_ZIP: &str = concat!(
        "504b0304330001006300c105515d000000002e0000001200000009000b00706c61696e2e7478740199070002004145030000d97a1d1bf374",
        "156c92f3171f04137339d16af5ccc6ec3cb049dbb216667ae9daa015a07b91d0b4bf602ffd76c8de504b01023f03330001006300c105515d",
        "000000002e0000001200000009002f000000000000002080a48100000000706c61696e2e7478740a00200000000000010018003a48cfc7a2",
        "5ddd01000000000000000000000000000000000199070002004145030000504b0506000000000100010066000000600000000000",
    );

    const ZIPCRYPTO_ZIP: &str = concat!(
        "504b0304140001000000c105515da120e1991e0000001200000009000000706c61696e2e7478745e9e18243ecda4a6be2a90891041a66bed",
        "81bbf02eca3e960b42530a1e19504b01023f03140001000000c105515da120e1991e00000012000000090024000000000000002080a48100",
        "000000706c61696e2e7478740a00200000000000010018003a48cfc7a25ddd0100000000000000000000000000000000504b050600000000",
        "010001005b000000450000000000",
    );

    fn aes_context(data: &[u8]) -> AesContext {
        match extract_zip_info(data) {
            Some(ZipEncryption::Aes(ctx)) => ctx,
            _ => panic!("expected an AES-encrypted zip"),
        }
    }

    #[test]
    fn pbkdf2_matches_known_vector() {
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 1000, &mut out);
        assert_eq!(
            out.to_vec(),
            decode_hex("6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214")
        );
    }

    #[test]
    fn batched_verification_matches_single() {
        let data = decode_hex(AES256_ZIP);
        let ctx = aes_context(&data);
        let long = vec![b'k'; 100];
        let passwords: [&[u8]; LANES] = [
            b"secret",
            long.as_slice(),
            b"",
            b"sec",
            b"secre",
            b"secrett",
            b"secr",
            b"s",
        ];
        let hits = verify_passwords_aes(&passwords, &ctx, &data);
        for (lane, password) in passwords.iter().enumerate() {
            assert_eq!(
                hits[lane],
                verify_password_aes(password, &ctx, &data),
                "lane {lane}"
            );
        }
        assert!(hits[0]);
        assert!(hits[1..].iter().all(|&hit| !hit));
    }

    #[test]
    fn batched_pbkdf2_matches_reference_for_all_key_sizes() {
        for key_len in [16usize, 24, 32] {
            for salt_len in [8usize, 12, 16] {
                let salt: Vec<u8> = (0..salt_len as u8)
                    .map(|b| b.wrapping_mul(37).wrapping_add(3))
                    .collect();
                for password in [b"secret".as_slice(), b"".as_slice(), &[b'x'; 100]] {
                    let dk_len = 2 * key_len + 2;
                    let mut reference = vec![0u8; dk_len];
                    pbkdf2::pbkdf2_hmac::<Sha1>(password, &salt, 1000, &mut reference);

                    let ciphertext = [0u8; 8];
                    let mut mac =
                        Hmac::<Sha1>::new_from_slice(&reference[key_len..2 * key_len]).unwrap();
                    mac.update(&ciphertext);
                    let tag = mac.finalize().into_bytes();

                    let ctx = AesContext {
                        salt: salt.clone(),
                        verifier: [reference[2 * key_len], reference[2 * key_len + 1]],
                        auth_code: tag[..10].try_into().unwrap(),
                        ciphertext: 0..ciphertext.len(),
                        key_len,
                    };

                    let hits = verify_passwords_aes(
                        &[
                            password, b"nope", b"nope2", b"nope3", b"nope4", b"nope5", b"nope6",
                            b"nope7",
                        ],
                        &ctx,
                        &ciphertext,
                    );
                    assert!(
                        hits[0],
                        "key_len={key_len} salt_len={salt_len} pw={password:?}"
                    );
                    assert!(hits[1..].iter().all(|&hit| !hit));
                }
            }
        }
    }

    #[test]
    fn cracks_aes128_zip() {
        let data = decode_hex(AES128_ZIP);
        let ctx = aes_context(&data);
        assert!(verify_password_aes(b"secret", &ctx, &data));
        assert!(!verify_password_aes(b"secret!", &ctx, &data));
    }

    #[test]
    fn cracks_aes192_zip() {
        let data = decode_hex(AES192_ZIP);
        let ctx = aes_context(&data);
        assert!(verify_password_aes(b"secret", &ctx, &data));
        assert!(!verify_password_aes(b"secret!", &ctx, &data));
    }

    #[test]
    fn cracks_aes256_zip() {
        let data = decode_hex(AES256_ZIP);
        let ctx = aes_context(&data);
        assert!(verify_password_aes(b"secret", &ctx, &data));
        assert!(!verify_password_aes(b"secret!", &ctx, &data));
    }

    #[test]
    fn cracks_aes_with_data_descriptor() {
        // Set the streaming data-descriptor bit and blank the local compressed
        // size; the parser must fall back to the central directory size.
        let mut data = decode_hex(AES192_ZIP);
        data[6] |= 1 << 3;
        data[18..22].copy_from_slice(&[0, 0, 0, 0]);
        match extract_zip_info(&data) {
            Some(ZipEncryption::Aes(ctx)) => {
                assert!(verify_password_aes(b"secret", &ctx, &data));
            }
            _ => panic!("expected an AES-encrypted zip"),
        }
    }

    #[test]
    fn cracks_pkware_zipcrypto_zip() {
        let data = decode_hex(ZIPCRYPTO_ZIP);
        match extract_zip_info(&data) {
            Some(ZipEncryption::Traditional(ctx)) => {
                assert!(verify_password_full(b"secret", &ctx, &data));
                assert!(!verify_password_full(b"wrong", &ctx, &data));
            }
            _ => panic!("expected a traditional PKWARE encrypted zip"),
        }
    }

    #[test]
    fn cracks_pkware_zipcrypto_deflate_zip() {
        // Deflate entry with a data descriptor, generated with Info-ZIP `zip`
        // (user = "secret"); the payload spans several decrypt chunks.
        let data: &[u8] = include_bytes!("../tests/fixtures/zipcrypto_deflate.zip");
        match extract_zip_info(data) {
            Some(ZipEncryption::Traditional(ctx)) => {
                assert!(verify_password_full(b"secret", &ctx, data));
                assert!(!verify_password_full(b"wrong", &ctx, data));
            }
            _ => panic!("expected a traditional PKWARE encrypted zip"),
        }
    }

    #[test]
    fn paired_verification_matches_single() {
        let archives = [
            decode_hex(ZIPCRYPTO_ZIP),
            include_bytes!("../tests/fixtures/zipcrypto_deflate.zip").to_vec(),
        ];
        let candidates: [&[u8]; 8] = [
            b"secret", b"wrong", b"wrong0", b"secret!", b"", b"s", b"sec", b"wrong1",
        ];
        for data in archives {
            let ctx = match extract_zip_info(&data) {
                Some(ZipEncryption::Traditional(ctx)) => ctx,
                _ => panic!("expected a traditional PKWARE encrypted zip"),
            };
            for pair in candidates.chunks_exact(2) {
                let (a, b) = verify_with_keys_pair(
                    PkwareKeys::new(pair[0]),
                    PkwareKeys::new(pair[1]),
                    &ctx,
                    &data,
                );
                assert_eq!(a, verify_password_full(pair[0], &ctx, &data));
                assert_eq!(b, verify_password_full(pair[1], &ctx, &data));
            }
            let (a, b) = verify_with_keys_pair(
                PkwareKeys::new(b"secret"),
                PkwareKeys::new(b"secret"),
                &ctx,
                &data,
            );
            assert!(a && b, "both lanes must match");
        }
    }
}
