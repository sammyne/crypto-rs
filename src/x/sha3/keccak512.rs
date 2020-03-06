use vendored_sha3::Digest;

use super::{Hash, BLOCK_SIZE512, SIZE512};

/// Keccak512 is re-exported and implements Hash.
pub use vendored_sha3::Keccak512;

impl Hash for Keccak512 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Keccak512::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE512
    }

    fn reset(&mut self) {
        Digest::reset(self);
    }

    fn sum(&mut self) -> Vec<u8> {
        let d = self.clone().result();
        let mut out = Vec::with_capacity(d.as_slice().len());
        out.extend_from_slice(d.as_slice());

        out
    }
}

/// new_legacy_keccak512 creates a new Keccak-512 hash.
///
/// Only use this function if you require compatibility with an existing cryptosystem that uses
/// non-standard padding. All other users should use new512 instead.
pub fn new_legacy_keccak512() -> Keccak512 {
    Hash::new()
}

/// keccak512 returns the Keccak-512 digest of the data.
pub fn keccak512(b: &[u8]) -> [u8; SIZE512] {
    let d = Keccak512::digest(b);

    let mut out = [0u8; SIZE512];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
