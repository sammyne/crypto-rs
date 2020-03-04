use sha3::Digest;

use super::{Hash, BLOCK_SIZE512, SIZE512};

pub use sha3::Keccak512;

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

pub fn new_legacy_keccak512() -> Keccak512 {
    Hash::new()
}

pub fn keccak512(b: &[u8]) -> [u8; SIZE512] {
    let d = Keccak512::digest(b);

    let mut out = [0u8; SIZE512];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
