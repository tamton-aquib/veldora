use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

/// Everything needed to check passwords of a WinZip AES (AE-1/AE-2) entry.
pub(crate) struct AesContext {
    pub salt: Vec<u8>,
    pub verifier: [u8; 2],
    pub auth_code: [u8; 10],
    pub ciphertext: Vec<u8>,
    pub key_len: usize,
}

/// Fixed by the WinZip AES specification (AE-1/AE-2).
const PBKDF2_ROUNDS: u32 = 1000;

#[inline]
pub(crate) fn verify_password_aes(password: &[u8], ctx: &AesContext) -> bool {
    // Derived material: [aes key][hmac key][2-byte password verifier]
    let mut derived = [0u8; 2 * 32 + 2];
    let dk_len = 2 * ctx.key_len + 2;
    pbkdf2_hmac::<Sha1>(password, &ctx.salt, PBKDF2_ROUNDS, &mut derived[..dk_len]);

    let mac_key = &derived[ctx.key_len..2 * ctx.key_len];
    if derived[2 * ctx.key_len..dk_len] != ctx.verifier {
        return false;
    }

    // The 2-byte verifier gives a 1-in-65536 false positive rate, so confirm
    // the match against the truncated HMAC-SHA1 authentication code.
    let mut mac = Hmac::<Sha1>::new_from_slice(mac_key).expect("HMAC accepts any key length");
    mac.update(&ctx.ciphertext);
    mac.finalize().into_bytes()[..10] == ctx.auth_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip_crypto::verify_password_full;
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

    fn aes_context(hex: &str) -> AesContext {
        match extract_zip_info(&decode_hex(hex)) {
            Some(ZipEncryption::Aes(ctx)) => ctx,
            _ => panic!("expected an AES-encrypted zip"),
        }
    }

    #[test]
    fn pbkdf2_matches_known_vector() {
        let mut out = [0u8; 32];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 1000, &mut out);
        assert_eq!(
            out.to_vec(),
            decode_hex("6e88be8bad7eae9d9e10aa061224034fed48d03fcbad968b56006784539d5214")
        );
    }

    #[test]
    fn cracks_aes128_zip() {
        let ctx = aes_context(AES128_ZIP);
        assert!(verify_password_aes(b"secret", &ctx));
        assert!(!verify_password_aes(b"secret!", &ctx));
    }

    #[test]
    fn cracks_aes192_zip() {
        let ctx = aes_context(AES192_ZIP);
        assert!(verify_password_aes(b"secret", &ctx));
        assert!(!verify_password_aes(b"secret!", &ctx));
    }

    #[test]
    fn cracks_aes256_zip() {
        let ctx = aes_context(AES256_ZIP);
        assert!(verify_password_aes(b"secret", &ctx));
        assert!(!verify_password_aes(b"secret!", &ctx));
    }

    #[test]
    fn cracks_aes_with_data_descriptor() {
        // Set the streaming data-descriptor bit and blank the local compressed
        // size; the parser must fall back to the central directory size.
        let mut data = decode_hex(AES192_ZIP);
        data[6] |= 1 << 3;
        data[18..22].copy_from_slice(&[0, 0, 0, 0]);
        match extract_zip_info(&data) {
            Some(ZipEncryption::Aes(ctx)) => assert!(verify_password_aes(b"secret", &ctx)),
            _ => panic!("expected an AES-encrypted zip"),
        }
    }

    #[test]
    fn cracks_pkware_zipcrypto_zip() {
        match extract_zip_info(&decode_hex(ZIPCRYPTO_ZIP)) {
            Some(ZipEncryption::Traditional(ctx)) => {
                assert!(verify_password_full(b"secret", &ctx));
                assert!(!verify_password_full(b"wrong", &ctx));
            }
            _ => panic!("expected a traditional PKWARE encrypted zip"),
        }
    }
}
