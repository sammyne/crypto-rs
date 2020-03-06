use vendored_sha3::Digest;

use super::{Hash, BLOCK_SIZE256, SIZE256};

pub use vendored_sha3::Keccak256;

impl Hash for Keccak256 {
    fn new() -> Self {
        Digest::new()
    }

    fn size() -> usize {
        Keccak256::output_size()
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

pub fn new_legacy_keccak256() -> Keccak256 {
    Hash::new()
}

pub fn keccak256(b: &[u8]) -> [u8; SIZE256] {
    let d = Keccak256::digest(b);

    let mut out = [0u8; SIZE256];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
