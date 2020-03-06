use vendored_sha3::{Digest, Sha3_224};

use super::Hash;

pub type SHA3_224 = Sha3_224;

pub const BLOCK_SIZE224: usize = 144;
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

pub fn new224() -> SHA3_224 {
    Hash::new()
}

pub fn sum224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha3_224::digest(b);

    let mut out = [0u8; SIZE224];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
