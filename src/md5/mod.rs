use std::io::{self, Write};

use md5::{Digest, Md5};

pub use super::Hash;

pub struct MD5(Md5);

pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 16;

impl Hash for MD5 {
    fn new() -> Self {
        Self(Md5::new())
    }

    fn size() -> usize {
        Md5::output_size()
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

impl Write for MD5 {
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.input(buf);

        Ok(buf.len())
    }
}

pub fn sum(b: &[u8]) -> [u8; SIZE] {
    let d = Md5::digest(b);

    let mut out = [0u8; SIZE];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
