#[inline(always)]
pub(crate) fn rc4_encrypt(key: &[u8], data: &mut [u8]) {
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
