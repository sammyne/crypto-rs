use sha2::{Digest, Sha224, Sha256};
use std::io::{self, Write};

pub use super::Hash;

pub struct Engine<T: Clone + Digest>(T);

pub type SHA224 = Engine<Sha224>;
pub type SHA256 = Engine<Sha256>;

pub const BLOCK_SIZE: usize = 64;
pub const SIZE: usize = 32;
pub const SIZE224: usize = 28;

impl<T: Clone + Digest> Hash for Engine<T> {
    fn new() -> Self {
        Self(T::new())
    }

    fn size() -> usize {
        T::output_size()
    }

    fn block_size() -> usize {
        BLOCK_SIZE
    }

    fn reset(&mut self) {
        self.0.reset()
    }

    fn sum(&mut self) -> Vec<u8> {
        let d = self.0.clone().result();
        let mut out = Vec::with_capacity(d.as_slice().len());
        out.extend_from_slice(d.as_slice());

        out
    }
}

impl<T: Clone + Digest> Write for Engine<T> {
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.input(buf);

        Ok(buf.len())
    }
}

pub fn sum224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha224::digest(b);

    let mut out = [0u8; SIZE224];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}

pub fn sum256(b: &[u8]) -> [u8; SIZE] {
    let d = Sha256::digest(b);

    let mut out = [0u8; SIZE];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
