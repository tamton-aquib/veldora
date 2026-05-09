use aes::{
    Aes128, Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, consts::U16, generic_array::GenericArray},
};

pub(crate) type Block16 = GenericArray<u8, U16>;

pub(crate) fn aes_128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut buf = data.to_vec();
    let cipher = Aes128::new_from_slice(key).unwrap();
    let mut prev = Block16::clone_from_slice(iv);
    for chunk in buf.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        cipher.encrypt_block(block);
        prev.copy_from_slice(&block[..]);
    }
    buf
}

#[allow(dead_code)]
pub(crate) fn aes_256_cbc_decrypt(key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    if data.len() < 16 || data.len() % 16 != 0 {
        return Vec::new();
    }

    let mut buf = data.to_vec();
    let cipher = Aes256::new_from_slice(key).unwrap();
    let zero_iv = Block16::default();
    let mut prev = zero_iv;

    for chunk in buf.chunks_exact_mut(16) {
        let block = GenericArray::from_mut_slice(chunk);
        let saved = *block;
        cipher.decrypt_block(block);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        prev = saved;
    }

    let pad_len = *buf.last().unwrap_or(&0) as usize;
    if pad_len > 0 && pad_len <= 16 {
        buf.truncate(buf.len() - pad_len);
    }
    buf
}
