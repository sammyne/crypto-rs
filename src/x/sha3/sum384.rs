use vendored_sha3::{Digest, Sha3_384};

use super::Hash;

/// SHA3_384 alias Sha3_384 and implements Hash.
pub type SHA3_384 = Sha3_384;

/// The blocksize of SHA3-384 in bytes.
pub const BLOCK_SIZE384: usize = 104;
/// The size of a SHA3-384 checksum in bytes.
pub const SIZE384: usize = 48;

impl Hash for SHA3_384 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Sha3_384::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE384
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

/// new384 creates a new SHA3-384 hash. Its generic security strength is 384 bits against preimage
/// attacks, and 192 bits against collision attacks.
pub fn new384() -> SHA3_384 {
    Hash::new()
}

/// sum384 returns the SHA3-384 digest of the data.
pub fn sum384(b: &[u8]) -> [u8; SIZE384] {
    let d = Sha3_384::digest(b);

    let mut out = [0u8; SIZE384];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
