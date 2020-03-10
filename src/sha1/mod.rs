//! module sha1 implements the SHA-1 hash algorithm as defined in [RFC 3174][1].
//!
//! SHA-1 is cryptographically broken and should not be used for secure applications.
//!
//! [1]: https://datatracker.ietf.org/doc/rfc3174/

use sha1::{Digest, Sha1};

/// SHA1 alias Sha3_256 and implements crate::Hash.
pub type SHA1 = Sha1;

/// The blocksize of SHA-1 in bytes.
pub const BLOCK_SIZE: usize = 64;
/// The size of a SHA-1 checksum in bytes.
pub const SIZE: usize = 20;

impl crate::Hash for SHA1 {
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

/// new returns a new hash.Hash computing the SHA-1 checksum.
pub fn new() -> SHA1 {
    SHA1::new()
}

/// sum returns the SHA-1 checksum of the data.
pub fn sum(b: &[u8]) -> [u8; SIZE] {
    let d = SHA1::digest(b);

    let mut out = [0u8; SIZE];
    out.copy_from_slice(d.as_slice());

    out
}
