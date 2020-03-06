use vendored_sha3::{Digest, Sha3_224};

use super::Hash;

/// SHA3_224 alias Sha3_224 and implements Hash.
pub type SHA3_224 = Sha3_224;

/// The blocksize of SHA3-224 in bytes.
pub const BLOCK_SIZE224: usize = 144;
/// The size of a SHA3-224 checksum in bytes.
pub const SIZE224: usize = 28;

impl Hash for SHA3_224 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Sha3_224::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE224
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

/// new224 creates a new SHA3-224 hash. Its generic security strength is 224 bits against preimage
/// attacks, and 112 bits against collision attacks.
pub fn new224() -> SHA3_224 {
    Hash::new()
}

/// sum224 returns the SHA3-224 digest of the data.
pub fn sum224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha3_224::digest(b);

    let mut out = [0u8; SIZE224];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
