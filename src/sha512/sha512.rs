use sha2::{Digest, Sha512};

pub const SIZE: usize = 64;

pub type SHA512 = Sha512;

impl super::Hash for SHA512 {
    fn size() -> usize {
        SHA512::output_size()
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

pub fn new() -> SHA512 {
    Digest::new()
}

pub fn sum512(b: &[u8]) -> [u8; SIZE] {
    let d = Sha512::digest(b);

    let mut out = [0u8; SIZE];
    out.copy_from_slice(d.as_slice());

    out
}
