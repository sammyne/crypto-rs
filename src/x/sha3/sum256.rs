use vendored_sha3::{Digest, Sha3_256};

/// SHA3_256 alias Sha3_256 and implements crate::Hash.
pub type SHA3_256 = Sha3_256;

/// The blocksize of SHA3-256 and Keccak-256 in bytes.
pub const BLOCK_SIZE256: usize = 136;
/// The size of a SHA3-256 and Keccak-256 checksum in bytes.
pub const SIZE256: usize = 32;

impl crate::Hash for SHA3_256 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Sha3_256::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE256
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

/// new256 creates a new SHA3-256 hash. Its generic security strength is 256 bits against preimage
/// attacks, and 128 bits against collision attacks.
pub fn new256() -> SHA3_256 {
    crate::Hash::new()
}

/// sum256 returns the SHA3-256 digest of the data.
pub fn sum256(b: &[u8]) -> [u8; SIZE256] {
    let d = Sha3_256::digest(b);

    let mut out = [0u8; SIZE256];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
