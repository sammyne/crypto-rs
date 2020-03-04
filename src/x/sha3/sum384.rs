use sha3::{Digest, Sha3_384};

use super::Hash;

pub type SHA3_384 = Sha3_384;

pub const BLOCK_SIZE384: usize = 104;
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

pub fn new384() -> SHA3_384 {
    Hash::new()
}

pub fn sum384(b: &[u8]) -> [u8; SIZE384] {
    let d = Sha3_384::digest(b);

    let mut out = [0u8; SIZE384];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
