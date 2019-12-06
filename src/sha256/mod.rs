use sha2::{Digest, Sha256};

pub use super::Hash;

pub struct SHA256(Sha256);

impl super::Hash for SHA256 {
    fn new() -> Self {
        SHA256(Sha256::default())
    }

    fn size() -> usize {
        Sha256::output_size()
    }

    fn block_size() -> usize {
        64
    }

    fn reset(&mut self) {
        self.0.reset()
    }

    fn sum(&self) -> Vec<u8> {
        let d = self.0.clone().result();
        let mut out = Vec::with_capacity(d.as_slice().len());
        out.extend_from_slice(d.as_slice());

        out
    }

    fn write(&mut self, buf: &[u8]) -> Result<usize, String> {
        self.0.input(buf);

        Ok(buf.len())
    }
}

pub fn sum256(b: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(b);

    let mut out = [0u8; 32];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
