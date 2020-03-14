use sha2::{Digest, Sha512Trunc256};

pub const SIZE256: usize = 32;

pub type SHA512_256 = Sha512Trunc256;

impl super::Hash for SHA512_256 {
    fn size() -> usize {
        SHA512_256::output_size()
    }

    fn block_size() -> usize {
        super::BLOCK_SIZE
    }

    fn reset(&mut self) {
        Digest::reset(self)
    }

    fn sum(&mut self) -> Vec<u8> {
        self.clone().result().as_slice().to_vec()
    }
}

pub fn new512_256() -> SHA512_256 {
    Digest::new()
}

pub fn sum512_256(b: &[u8]) -> [u8; SIZE256] {
    let d = Sha512Trunc256::digest(b);

    let mut out = [0u8; SIZE256];
    out.copy_from_slice(d.as_slice());

    out
}
