//! module rc4 implements RC4 encryption, as defined in Bruce Schneier's Applied Cryptography.
//!
//! RC4 is cryptographically broken and should not be used for secure applications.

use crate::internal::subtle;

/// Cipher is an instance of RC4 using a particular key.
pub struct Cipher {
    states: [u8; 256],
    i: u8,
    j: u8,
}

/// Error enumerations related cryptographic operations in this module
#[derive(Debug)]
pub enum Error {
    KeySize(usize),
}

impl Cipher {
    /// Reset zeros the key data and makes the Cipher unusable.
    ///
    /// Deprecated: Reset can't guarantee that the key will be entirely removed from the process's
    /// memory.
    pub fn reset(&mut self) {
        for v in &mut self.states[..] {
            *v = 0;
        }

        self.i = 0;
        self.j = 0;
    }

    /// xor_key_stream sets dst to the result of XORing src with the key stream. Dst and src must
    /// overlap entirely or not at all.
    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        if src.len() == 0 {
            return;
        }

        if subtle::inexact_overlap(dst, src) {
            panic!("crypto/rc4: invalid buffer overlap")
        }

        let mut i = self.i;
        let mut j = self.j;

        let _ = dst[src.len() - 1];
        let (dst, ..) = dst.split_at_mut(src.len()); // eliminate bounds check from loop
        for (k, v) in src.iter().enumerate() {
            i = i.wrapping_add(1);
            let x = self.states[i as usize];
            j = j.wrapping_add(x);
            let y = self.states[j as usize];

            self.states[i as usize] = y;
            self.states[j as usize] = x;
            dst[k] = v ^ self.states[x.wrapping_add(y) as usize];
        }

        self.i = i;
        self.j = j;
    }
}

impl Drop for Cipher {
    /// drop calles self.reset internally.
    fn drop(&mut self) {
        self.reset()
    }
}

/// NewCipher creates and returns a new Cipher. The key argument should be the RC4 key, at least 1
/// byte and at most 256 bytes.
/// Aliased to rc4.NewCipher in go.
pub fn new(key: &[u8]) -> Result<Cipher, Error> {
    let key_len = key.len();
    if key_len < 1 || key_len > 256 {
        return Err(Error::KeySize(key_len));
    }

    let mut states = [0u8; 256];
    for i in 0..states.len() {
        states[i] = i as u8;
    }

    let mut j = 0u8;
    for i in 0..states.len() {
        j = j.wrapping_add(states[i].wrapping_add(key[i % key_len]));

        let tmp = states[i];
        states[i] = states[j as usize];
        states[j as usize] = tmp;
    }
    Ok(Cipher { states, i: 0, j: 0 })
}
