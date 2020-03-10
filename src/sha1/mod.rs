use sha1::{Digest, Sha1};

/// SHA1 alias Sha3_256 and implements crate::Hash.
pub type SHA1 = Sha1;

/// The blocksize of SHA1 and Keccak-256 in bytes.
pub const BLOCK_SIZE: usize = 64;
/// The size of a SHA1 and Keccak-256 checksum in bytes.
pub const SIZE: usize = 20;

impl crate::Hash for SHA1 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Sha1::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        Digest::reset(self);
    }

    fn sum(&mut self) -> Vec<u8> {
        self.clone().result().to_vec()
    }
}

/// new256 creates a new SHA1 hash. Its generic security strength is 256 bits against preimage
/// attacks, and 128 bits against collision attacks.
pub fn new() -> SHA1 {
    crate::Hash::new()
}

/// sum returns the SHA1 digest of the data.
pub fn sum(b: &[u8]) -> [u8; SIZE] {
    let d = SHA1::digest(b);

    let mut out = [0u8; SIZE];
    out.copy_from_slice(d.as_slice());

    out
}
