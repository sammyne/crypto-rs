use std::io::{self, Write};

use ripemd160::{Digest, Ripemd160};

pub use super::Hash;

pub struct RIPEMD160(Ripemd160);

pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 20;

impl Hash for RIPEMD160 {
    fn new() -> Self {
        Self(Ripemd160::new())
    }

    fn size() -> usize {
        Ripemd160::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
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
}

impl Write for RIPEMD160 {
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.input(buf);

        Ok(buf.len())
    }
}

pub fn sum(b: &[u8]) -> [u8; SIZE] {
    let d = Ripemd160::digest(b);

    let mut out = [0u8; SIZE];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
