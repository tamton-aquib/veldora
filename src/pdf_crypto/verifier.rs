use crate::pdf_crypto::kdf::{
    compute_u_rev_3_4, derive_key_owner, derive_key_user, hash_v5, PADDING,
};
use crate::pdf_crypto::parser::PdfCryptoContext;
use crate::pdf_crypto::rc4::rc4_encrypt;
use stringprep::saslprep;

impl PdfCryptoContext {
    pub fn verify_password(&self, pass: &[u8]) -> bool {
        match self.r {
            2 => self.verify_r2(pass),
            3 | 4 => self.verify_r34(pass),
            5 | 6 => self.verify_r56(pass),
            _ => false,
        }
    }

    fn verify_r2(&self, pass: &[u8]) -> bool {
        let key = derive_key_user(pass, self);
        let mut u_computed = PADDING;
        rc4_encrypt(&key[..self.key_size], &mut u_computed);
        if u_computed[..self.u_len] == self.u[..self.u_len] {
            return true;
        }

        // Owner password path: Algorithm 7 without the revision 3 iterations.
        let owner_key = derive_key_owner(pass, self);
        let mut decrypted_o = [0u8; 48];
        decrypted_o[..self.o_len].copy_from_slice(&self.o[..self.o_len]);
        rc4_encrypt(&owner_key[..self.key_size], &mut decrypted_o[..self.o_len]);

        let user_pass = &decrypted_o[..32];
        let user_key = derive_key_user(user_pass, self);
        let mut u_computed2 = PADDING;
        rc4_encrypt(&user_key[..self.key_size], &mut u_computed2);
        u_computed2[..self.u_len] == self.u[..self.u_len]
    }

    fn verify_r34(&self, pass: &[u8]) -> bool {
        let key = derive_key_user(pass, self);
        let u_computed = compute_u_rev_3_4(&self.id[..self.id_len], &key[..self.key_size]);
        if u_computed == self.u[..16] {
            return true;
        }

        let owner_key = derive_key_owner(pass, self);
        let mut decrypted_o = [0u8; 48];
        decrypted_o[..self.o_len].copy_from_slice(&self.o[..self.o_len]);
        rc4_encrypt(&owner_key[..self.key_size], &mut decrypted_o[..self.o_len]);
        for i in 1u8..=19 {
            let mut round_key = [0u8; 16];
            round_key[..self.key_size].copy_from_slice(&owner_key[..self.key_size]);
            for b in &mut round_key[..self.key_size] {
                *b ^= i;
            }
            rc4_encrypt(&round_key[..self.key_size], &mut decrypted_o[..self.o_len]);
        }

        let user_pass = &decrypted_o[..32];
        let user_key = derive_key_user(user_pass, self);
        let u_computed2 = compute_u_rev_3_4(&self.id[..self.id_len], &user_key[..self.key_size]);
        u_computed2 == self.u[..16]
    }

    fn verify_r56(&self, pass: &[u8]) -> bool {
        if self.r == 6 && !pass.is_ascii() {
            // Revision 6 applies SASLprep (RFC 4013) before hashing. pdf.js
            // also retries the raw password when preparation changed it.
            if let Ok(password) = std::str::from_utf8(pass) {
                if let Ok(prepped) = saslprep(password) {
                    if prepped != password && self.verify_r56_bytes(prepped.as_bytes()) {
                        return true;
                    }
                }
            }
        }

        self.verify_r56_bytes(pass)
    }

    fn verify_r56_bytes(&self, pass: &[u8]) -> bool {
        if self.u_len >= 40 {
            let salt: &[u8; 8] = (&self.u[32..40]).try_into().unwrap();
            let expected: &[u8; 32] = (&self.u[..32]).try_into().unwrap();
            let computed = hash_v5(pass, salt, &[], self.r);
            if computed == *expected {
                return true;
            }
        }

        if self.o_len >= 40 && self.u_len >= 48 {
            let salt: &[u8; 8] = (&self.o[32..40]).try_into().unwrap();
            let expected: &[u8; 32] = (&self.o[..32]).try_into().unwrap();
            let computed = hash_v5(pass, salt, &self.u[..48], self.r);
            if computed == *expected {
                return true;
            }
        }

        false
    }
}
