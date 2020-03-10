use vendored_sha3::{Digest, Sha3_512};

/// SHA3_512 alias Sha3_512 and implements Hash.
pub type SHA3_512 = Sha3_512;

/// The blocksize of SHA3-512 and Keccak-512 in bytes.
pub const BLOCK_SIZE512: usize = 72;
/// The size of a SHA3-512 and Keccak-512 checksum in bytes.
pub const SIZE512: usize = 64;

impl super::Hash for SHA3_512 {
    fn size() -> usize {
        Sha3_512::output_size()
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

/// new512 creates a new SHA3-512 hash. Its generic security strength is 512 bits against preimage
/// attacks, and 256 bits against collision attacks.
pub fn new512() -> SHA3_512 {
    Digest::new()
}

/// sum512 returns the SHA3-512 digest of the data.
pub fn sum512(b: &[u8]) -> [u8; SIZE512] {
    let d = Sha3_512::digest(b);

    let mut out = [0u8; SIZE512];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
