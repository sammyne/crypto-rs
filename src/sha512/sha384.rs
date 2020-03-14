use sha2::{Digest, Sha384};

pub const SIZE384: usize = 48;

pub type SHA384 = Sha384;

impl super::Hash for SHA384 {
    fn size() -> usize {
        SHA384::output_size()
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

pub fn new384() -> SHA384 {
    Digest::new()
}

pub fn sum384(b: &[u8]) -> [u8; SIZE384] {
    let d = Sha384::digest(b);

    let mut out = [0u8; SIZE384];
    out.copy_from_slice(d.as_slice());

    out
}
