use sha2::{Digest, Sha512Trunc224};

pub const SIZE224: usize = 28;

pub type SHA512_224 = Sha512Trunc224;

impl super::Hash for SHA512_224 {
    fn size() -> usize {
        SHA512_224::output_size()
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

pub fn new512_224() -> SHA512_224 {
    Digest::new()
}

pub fn sum512_224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha512Trunc224::digest(b);

    let mut out = [0u8; SIZE224];
    out.copy_from_slice(d.as_slice());

    out
}
