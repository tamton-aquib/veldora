//! Four independent SHA-1 state updates per call.
//!
//! WinZip AES cracking runs PBKDF2 for many candidate passwords. Those chains
//! are independent, so four of them can be hashed in lockstep: the four
//! compression functions are emitted back to back and the CPU overlaps their
//! dependency chains, hiding the latency of the SHA extensions.
//!
//! The SHA-NI kernel is adapted from the `sha1` crate's x86 backend
//! (MIT/Apache-2.0) and falls back to it for a single lane at a time.

use sha1::digest::generic_array::GenericArray;
use sha1::digest::typenum::U64;

/// Number of candidates processed together.
pub(crate) const LANES: usize = 4;

/// Runs the SHA-1 compression function for four independent states.
pub(crate) fn compress4(states: &mut [[u32; 5]; LANES], blocks: &[[u8; 64]; LANES]) {
    #[cfg(target_arch = "x86_64")]
    {
        if sha_ni_available() {
            // SAFETY: guarded by runtime CPU feature detection.
            unsafe { compress4_sha_ni(states, blocks) };
            return;
        }
    }

    for (state, block) in states.iter_mut().zip(blocks.iter()) {
        sha1::compress(state, &[GenericArray::<u8, U64>::clone_from_slice(block)]);
    }
}

#[cfg(target_arch = "x86_64")]
fn sha_ni_available() -> bool {
    std::arch::is_x86_feature_detected!("sha")
        && std::arch::is_x86_feature_detected!("sse2")
        && std::arch::is_x86_feature_detected!("ssse3")
        && std::arch::is_x86_feature_detected!("sse4.1")
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress4_sha_ni(states: &mut [[u32; 5]; LANES], blocks: &[[u8; 64]; LANES]) {
    use core::arch::x86_64::*;

    macro_rules! rounds4 {
        ($h0:ident, $h1:ident, $wk:expr, $i:expr) => {
            _mm_sha1rnds4_epu32($h0, _mm_sha1nexte_epu32($h1, $wk), $i)
        };
    }

    macro_rules! schedule {
        ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
            _mm_sha1msg2_epu32(_mm_xor_si128(_mm_sha1msg1_epu32($v0, $v1), $v2), $v3)
        };
    }

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

    // One lane: compress `blocks[$i]` into `abcd[$i]` / `e[$i]`.
    macro_rules! lane {
        ($i:expr, $abcd:ident, $e:ident, $blocks:ident, $mask:ident) => {{
            let block_ptr = $blocks[$i].as_ptr() as *const __m128i;

            let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(0)), $mask);
            let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(1)), $mask);
            let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(2)), $mask);
            let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.offset(3)), $mask);
            #[allow(unused_assignments)]
            let mut w4 = _mm_setzero_si128();

            let mut h0 = $abcd[$i];
            let mut h1 = _mm_add_epi32($e[$i], w0);

            // Rounds 0..20
            h1 = _mm_sha1rnds4_epu32(h0, h1, 0);
            h0 = rounds4!(h1, h0, w1, 0);
            h1 = rounds4!(h0, h1, w2, 0);
            h0 = rounds4!(h1, h0, w3, 0);
            schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 0);

            // Rounds 20..40
            schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 1);
            schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 1);
            schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 1);
            schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 1);
            schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 1);

            // Rounds 40..60
            schedule_rounds4!(h0, h1, w1, w2, w3, w4, w0, 2);
            schedule_rounds4!(h1, h0, w2, w3, w4, w0, w1, 2);
            schedule_rounds4!(h0, h1, w3, w4, w0, w1, w2, 2);
            schedule_rounds4!(h1, h0, w4, w0, w1, w2, w3, 2);
            schedule_rounds4!(h0, h1, w0, w1, w2, w3, w4, 2);

            // Rounds 60..80
            schedule_rounds4!(h1, h0, w1, w2, w3, w4, w0, 3);
            schedule_rounds4!(h0, h1, w2, w3, w4, w0, w1, 3);
            schedule_rounds4!(h1, h0, w3, w4, w0, w1, w2, 3);
            schedule_rounds4!(h0, h1, w4, w0, w1, w2, w3, 3);
            schedule_rounds4!(h1, h0, w0, w1, w2, w3, w4, 3);

            $abcd[$i] = _mm_add_epi32($abcd[$i], h0);
            $e[$i] = _mm_sha1nexte_epu32(h1, $e[$i]);
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

    /// Deterministic pseudo random bytes for the comparison test.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn compress4_matches_single_compressions() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for round in 0..64 {
            let mut states = [[0u32; 5]; LANES];
            let mut blocks = [[0u8; 64]; LANES];
            for lane in 0..LANES {
                for word in &mut states[lane] {
                    *word = xorshift(&mut rng) as u32;
                }
                for chunk in blocks[lane].chunks_mut(8) {
                    chunk.copy_from_slice(&xorshift(&mut rng).to_le_bytes());
                }
            }

            let mut expected = states;
            for (state, block) in expected.iter_mut().zip(blocks.iter()) {
                sha1::compress(state, &[GenericArray::<u8, U64>::clone_from_slice(block)]);
            }

            compress4(&mut states, &blocks);
            assert_eq!(states, expected, "round {round}");
        }
    }
}
