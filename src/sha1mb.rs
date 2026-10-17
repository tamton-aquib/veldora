//! Multi-buffer SHA-1: several independent state updates per call.
//!
//! WinZip AES cracking runs PBKDF2 for many candidate passwords. Those chains
//! are independent, so they are hashed in lockstep: the compression functions
//! are emitted back to back and the CPU overlaps their dependency chains,
//! hiding the latency of the SHA extensions.
//!
//! The SHA-NI kernel is adapted from the `sha1` crate's x86 backend
//! (MIT/Apache-2.0); it falls back to that crate one lane at a time.

use sha1::digest::generic_array::GenericArray;
use sha1::digest::typenum::U64;

/// Number of independent states processed together.
pub(crate) const LANES: usize = 8;

/// Runs the SHA-1 compression function for `LANES` independent states.
pub(crate) fn compress(states: &mut [[u32; 5]; LANES], blocks: &[[u8; 64]; LANES]) {
    #[cfg(target_arch = "x86_64")]
    {
        if sha_ni_available() {
            // SAFETY: guarded by runtime CPU feature detection.
            unsafe { compress_sha_ni(states, blocks) };
            return;
        }
    }

    for (state, block) in states.iter_mut().zip(blocks.iter()) {
        sha1::compress(state, &[GenericArray::<u8, U64>::clone_from_slice(block)]);
    }
}

/// Like [`compress`], but the message is always a 20 byte digest. That is the
/// shape of every PBKDF2-HMAC iteration, so the constant tail words can be
/// built directly in registers instead of padding a whole block in memory.
pub(crate) fn compress_tail(states: &mut [[u32; 5]; LANES], digests: &[[u8; 20]; LANES]) {
    #[cfg(target_arch = "x86_64")]
    {
        if sha_ni_available() {
            // SAFETY: guarded by runtime CPU feature detection.
            unsafe { compress_tail_sha_ni(states, digests) };
            return;
        }
    }

    for (state, digest) in states.iter_mut().zip(digests.iter()) {
        sha1::compress(
            state,
            &[GenericArray::<u8, U64>::clone_from_slice(&tail_block(
                digest,
            ))],
        );
    }
}

/// Padded final block for a message of up to 55 bytes whose first 64 bytes are
/// already absorbed into a midstate.
pub(crate) fn tail_block(message: &[u8]) -> [u8; 64] {
    debug_assert!(message.len() <= 55);
    let mut block = [0u8; 64];
    block[..message.len()].copy_from_slice(message);
    block[message.len()] = 0x80;
    let bit_len = ((64 + message.len()) as u64) * 8;
    block[56..].copy_from_slice(&bit_len.to_be_bytes());
    block
}

#[cfg(target_arch = "x86_64")]
fn sha_ni_available() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

#[cfg(target_arch = "x86_64")]
macro_rules! rounds4 {
    ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
        _mm_sha1rnds4_epu32($h0, _mm_sha1nexte_epu32($h1, $wk), $i)
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! schedule {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32($v0, $v1), $v2), $v3)
    };
}

#[cfg(target_arch = "x86_64")]
macro_rules! schedule_rounds4 {
    (
        $h0:ident, $h1:ident,
        $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr,
        $i:expr
    ) => {
        $w4 = schedule!($w0, $w1, $w2, $w3);
        $h1 = rounds4!($h0, $h1, $w4, $i);
    };
}

/// The 80 SHA-1 rounds for one lane, updating `$abcd` and `$e`.
#[cfg(target_arch = "x86_64")]
macro_rules! sha1_lane {
    ($abcd:expr, $e:expr, $w0:ident, $w1:ident, $w2:ident, $w3:ident, $w4:ident) => {{
        let mut h0 = $abcd;
        let mut h1 = _mm_add_epi32($e, $w0);

        // Rounds 0..20
        h1 = _mm_sha1rnds4_epu32(h0, h1, 0);
        h0 = rounds4!(h1, h0, $w1, 0);
        h1 = rounds4!(h0, h1, $w2, 0);
        h0 = rounds4!(h1, h0, $w3, 0);
        schedule_rounds4!(h0, h1, $w0, $w1, $w2, $w3, $w4, 0);

        // Rounds 20..40
        schedule_rounds4!(h1, h0, $w1, $w2, $w3, $w4, $w0, 1);
        schedule_rounds4!(h0, h1, $w2, $w3, $w4, $w0, $w1, 1);
        schedule_rounds4!(h1, h0, $w3, $w4, $w0, $w1, $w2, 1);
        schedule_rounds4!(h0, h1, $w4, $w0, $w1, $w2, $w3, 1);
        schedule_rounds4!(h1, h0, $w0, $w1, $w2, $w3, $w4, 1);

        // Rounds 40..60
        schedule_rounds4!(h0, h1, $w1, $w2, $w3, $w4, $w0, 2);
        schedule_rounds4!(h1, h0, $w2, $w3, $w4, $w0, $w1, 2);
        schedule_rounds4!(h0, h1, $w3, $w4, $w0, $w1, $w2, 2);
        schedule_rounds4!(h1, h0, $w4, $w0, $w1, $w2, $w3, 2);
        schedule_rounds4!(h0, h1, $w0, $w1, $w2, $w3, $w4, 2);

        // Rounds 60..80
        schedule_rounds4!(h1, h0, $w1, $w2, $w3, $w4, $w0, 3);
        schedule_rounds4!(h0, h1, $w2, $w3, $w4, $w0, $w1, 3);
        schedule_rounds4!(h1, h0, $w3, $w4, $w0, $w1, $w2, 3);
        schedule_rounds4!(h0, h1, $w4, $w0, $w1, $w2, $w3, 3);
        schedule_rounds4!(h1, h0, $w0, $w1, $w2, $w3, $w4, 3);

        $abcd = _mm_add_epi32($abcd, h0);
        $e = _mm_sha1nexte_epu32(h1, $e);
    }};
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_sha_ni(states: &mut [[u32; 5]; LANES], blocks: &[[u8; 64]; LANES]) {
    use core::arch::x86_64::*;

    macro_rules! lane {
        ($i:expr, $abcd:ident, $e:ident, $blocks:ident, $mask:ident) => {{
            let block_ptr = $blocks[$i].as_ptr() as *const __m128i;

            let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(0)), $mask);
            let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(1)), $mask);
            let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(2)), $mask);
            let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(3)), $mask);
            #[allow(unused_assignments)]
            let mut w4 = _mm_setzero_si128();

            sha1_lane!($abcd[$i], $e[$i], w0, w1, w2, w3, w4);
        }};
    }

    let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F);

    let mut abcd = [_mm_setzero_si128(); LANES];
    let mut e = [_mm_setzero_si128(); LANES];
    for (lane, state) in states.iter().enumerate() {
        abcd[lane] = _mm_set_epi32(
            state[0] as i32,
            state[1] as i32,
            state[2] as i32,
            state[3] as i32,
        );
        e[lane] = _mm_set_epi32(state[4] as i32, 0, 0, 0);
    }

    lane!(0, abcd, e, blocks, mask);
    lane!(1, abcd, e, blocks, mask);
    lane!(2, abcd, e, blocks, mask);
    lane!(3, abcd, e, blocks, mask);
    lane!(4, abcd, e, blocks, mask);
    lane!(5, abcd, e, blocks, mask);
    lane!(6, abcd, e, blocks, mask);
    lane!(7, abcd, e, blocks, mask);

    for (lane, state) in states.iter_mut().enumerate() {
        state[0] = _mm_extract_epi32(abcd[lane], 3) as u32;
        state[1] = _mm_extract_epi32(abcd[lane], 2) as u32;
        state[2] = _mm_extract_epi32(abcd[lane], 1) as u32;
        state[3] = _mm_extract_epi32(abcd[lane], 0) as u32;
        state[4] = _mm_extract_epi32(e[lane], 3) as u32;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_tail_sha_ni(states: &mut [[u32; 5]; LANES], digests: &[[u8; 20]; LANES]) {
    use core::arch::x86_64::*;

    // For a 20 byte message, the padded block words after the data are
    // constant: W5 = 0x8000_0000 and W15 = (64 + 20) * 8.
    let tail_mask = _mm_setr_epi8(-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 3, 2, 1, 0);
    let tail_80 = _mm_set_epi32(0, 0x8000_0000u32 as i32, 0, 0);
    let tail_len = _mm_cvtsi32_si128((64 + 20) * 8);

    macro_rules! lane {
        ($i:expr, $abcd:ident, $e:ident, $digests:ident, $mask:ident) => {{
            let digest = &$digests[$i];

            let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(digest.as_ptr() as *const __m128i), $mask);
            let rest = _mm_cvtsi32_si128(i32::from_le_bytes([
                digest[16], digest[17], digest[18], digest[19],
            ]));
            let mut w1 = _mm_or_si128(_mm_shuffle_epi8(rest, tail_mask), tail_80);
            let mut w2 = _mm_setzero_si128();
            let mut w3 = tail_len;
            #[allow(unused_assignments)]
            let mut w4 = _mm_setzero_si128();

            sha1_lane!($abcd[$i], $e[$i], w0, w1, w2, w3, w4);
        }};
    }

    let mask = _mm_set_epi64x(0x0001_0203_0405_0607, 0x0809_0A0B_0C0D_0E0F);

    let mut abcd = [_mm_setzero_si128(); LANES];
    let mut e = [_mm_setzero_si128(); LANES];
    for (lane, state) in states.iter().enumerate() {
        abcd[lane] = _mm_set_epi32(
            state[0] as i32,
            state[1] as i32,
            state[2] as i32,
            state[3] as i32,
        );
        e[lane] = _mm_set_epi32(state[4] as i32, 0, 0, 0);
    }

    lane!(0, abcd, e, digests, mask);
    lane!(1, abcd, e, digests, mask);
    lane!(2, abcd, e, digests, mask);
    lane!(3, abcd, e, digests, mask);
    lane!(4, abcd, e, digests, mask);
    lane!(5, abcd, e, digests, mask);
    lane!(6, abcd, e, digests, mask);
    lane!(7, abcd, e, digests, mask);

    for (lane, state) in states.iter_mut().enumerate() {
        state[0] = _mm_extract_epi32(abcd[lane], 3) as u32;
        state[1] = _mm_extract_epi32(abcd[lane], 2) as u32;
        state[2] = _mm_extract_epi32(abcd[lane], 1) as u32;
        state[3] = _mm_extract_epi32(abcd[lane], 0) as u32;
        state[4] = _mm_extract_epi32(e[lane], 3) as u32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo random bytes for the comparison tests.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_states(rng: &mut u64) -> [[u32; 5]; LANES] {
        let mut states = [[0u32; 5]; LANES];
        for state in states.iter_mut() {
            for word in state.iter_mut() {
                *word = xorshift(rng) as u32;
            }
        }
        states
    }

    #[test]
    fn compress_matches_single_compressions() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for round in 0..32 {
            let states = random_states(&mut rng);
            let mut blocks = [[0u8; 64]; LANES];
            for block in blocks.iter_mut() {
                for chunk in block.chunks_mut(8) {
                    chunk.copy_from_slice(&xorshift(&mut rng).to_le_bytes());
                }
            }

            let mut expected = states;
            for (state, block) in expected.iter_mut().zip(blocks.iter()) {
                sha1::compress(state, &[GenericArray::<u8, U64>::clone_from_slice(block)]);
            }

            let mut actual = states;
            compress(&mut actual, &blocks);
            assert_eq!(actual, expected, "round {round}");
        }
    }

    #[test]
    fn compress_tail_matches_padded_block_compression() {
        let mut rng = 0x0fed_cba9_8765_4321u64;
        for round in 0..32 {
            let states = random_states(&mut rng);
            let mut digests = [[0u8; 20]; LANES];
            for digest in digests.iter_mut() {
                for chunk in digest.chunks_mut(8) {
                    let bytes = xorshift(&mut rng).to_le_bytes();
                    chunk.copy_from_slice(&bytes[..chunk.len()]);
                }
            }

            let mut expected = states;
            compress(&mut expected, &digests.map(|digest| tail_block(&digest)));

            let mut actual = states;
            compress_tail(&mut actual, &digests);
            assert_eq!(actual, expected, "round {round}");
        }
    }
}
