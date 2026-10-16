use veldora::pdf_crypto::PdfCryptoContext;

// Fixtures were generated with pikepdf (qpdf) and verified with both the user
// and owner passwords: user = "secret", owner = "ownerpass".
fn verify_fixture(bytes: &[u8]) {
    let ctx = PdfCryptoContext::from_bytes(bytes.to_vec()).expect("failed to parse PDF");
    assert!(
        ctx.verify_password(b"secret"),
        "user password was not detected"
    );
    assert!(
        ctx.verify_password(b"ownerpass"),
        "owner password was not detected"
    );
    assert!(!ctx.verify_password(b"wrong"), "wrong password accepted");
}

#[test]
fn cracks_rc4_40_bit_pdf() {
    verify_fixture(include_bytes!("fixtures/rc4_40.pdf"));
}

#[test]
fn cracks_rc4_128_bit_pdf() {
    verify_fixture(include_bytes!("fixtures/rc4_128.pdf"));
}

#[test]
fn cracks_aes_128_pdf() {
    verify_fixture(include_bytes!("fixtures/aes_128.pdf"));
}

#[test]
fn cracks_aes_256_pdf() {
    verify_fixture(include_bytes!("fixtures/aes_256.pdf"));
}

#[test]
fn cracks_aes_256_pdf_with_unicode_password() {
    // Simulates a SASLprep-compliant writer (e.g. Acrobat): the stored
    // password is the prepared form ("password"), so an unprepped candidate
    // with a U+00AD soft hyphen must be prepared before hashing.
    let ctx = PdfCryptoContext::from_bytes(include_bytes!("fixtures/aes_256_prepped.pdf").to_vec())
        .expect("failed to parse PDF");
    assert!(ctx.verify_password("pa\u{00AD}ssword".as_bytes()));
    assert!(ctx.verify_password(b"password"));

    // This fixture stores the raw UTF-8 bytes; after the prepared candidate
    // fails, the raw password must still be retried.
    let ctx = PdfCryptoContext::from_bytes(include_bytes!("fixtures/aes_256_raw.pdf").to_vec())
        .expect("failed to parse PDF");
    assert!(ctx.verify_password("pa\u{00AD}ssword".as_bytes()));
}
