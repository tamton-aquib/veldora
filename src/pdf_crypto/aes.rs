use aes::{
    cipher::{consts::U16, generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes128,
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
