use vendored_sha3::{Digest, Sha3_512};

use super::Hash;

pub type SHA3_512 = Sha3_512;

pub const BLOCK_SIZE512: usize = 72;
pub const SIZE512: usize = 64;

impl Hash for SHA3_512 {
    fn new() -> Self {
        Digest::new()
    }

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

pub fn new512() -> SHA3_512 {
    Hash::new()
}

pub fn sum512(b: &[u8]) -> [u8; SIZE512] {
    let d = Sha3_512::digest(b);

    let mut out = [0u8; SIZE512];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
