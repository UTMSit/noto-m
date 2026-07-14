use sha2::{Digest, Sha256, Sha512};

pub struct CustomCipher {
    state: [u8; 64],
}

impl CustomCipher {
    pub fn new(shared_secret: &[u8; 32], nonce: &[u8; 16]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(shared_secret);
        hasher.update(nonce);
        let hash = hasher.finalize();
        let mut state = [0u8; 64];
        state.copy_from_slice(&hash);
        Self { state }
    }

    fn permute(&mut self) {
        let mut words = [0u64; 8];
        for i in 0..8 {
            words[i] = u64::from_le_bytes(self.state[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        let a: u64 = 6364136223846793005;
        let c: u64 = 1442695040888963407;

        for i in 0..8 {
            words[i] = words[i].wrapping_mul(a).wrapping_add(c);
            words[i] ^= words[(i + 1) % 8].rotate_left(17);
        }

        for i in 0..8 {
            self.state[i * 8..(i + 1) * 8].copy_from_slice(&words[i].to_le_bytes());
        }

        let mut hasher = Sha512::new();
        hasher.update(self.state);
        let hash = hasher.finalize();
        self.state.copy_from_slice(&hash);
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let chunks = plaintext.chunks(32);

        for chunk in chunks {
            self.permute();

            let mut hasher = Sha256::new();
            hasher.update(self.state);
            let keystream = hasher.finalize();

            let mut encrypted_chunk = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                encrypted_chunk[i] = chunk[i] ^ keystream[i];
            }
            ciphertext.extend_from_slice(&encrypted_chunk);

            let mut absorb_hasher = Sha512::new();
            absorb_hasher.update(self.state);
            absorb_hasher.update(&encrypted_chunk);
            let new_state = absorb_hasher.finalize();
            self.state.copy_from_slice(&new_state);
        }

        ciphertext
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let chunks = ciphertext.chunks(32);

        for chunk in chunks {
            self.permute();

            let mut hasher = Sha256::new();
            hasher.update(self.state);
            let keystream = hasher.finalize();

            let mut decrypted_chunk = vec![0u8; chunk.len()];
            for i in 0..chunk.len() {
                decrypted_chunk[i] = chunk[i] ^ keystream[i];
            }
            plaintext.extend_from_slice(&decrypted_chunk);

            let mut absorb_hasher = Sha512::new();
            absorb_hasher.update(self.state);
            absorb_hasher.update(chunk);
            let new_state = absorb_hasher.finalize();
            self.state.copy_from_slice(&new_state);
        }

        plaintext
    }
}
