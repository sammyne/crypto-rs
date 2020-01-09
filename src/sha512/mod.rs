use sha2::{Digest, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use std::io::{self, Write};

pub use super::Hash;

pub const BLOCK_SIZE: usize = 128;

pub const SIZE224: usize = 28;
pub const SIZE256: usize = 32;
pub const SIZE384: usize = 48;
pub const SIZE: usize = 64;

pub struct Engine<T: Clone + Digest>(T);

pub type SHA384 = Engine<Sha384>;
pub type SHA512 = Engine<Sha512>;
pub type SHA512_224 = Engine<Sha512Trunc224>;
pub type SHA512_256 = Engine<Sha512Trunc256>;

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

pub fn sum384(b: &[u8]) -> [u8; SIZE384] {
    let d = Sha384::digest(b);

    let mut out = [0u8; SIZE384];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}

pub fn sum512(b: &[u8]) -> [u8; SIZE] {
    let d = Sha512::digest(b);

    let mut out = [0u8; SIZE];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}

pub fn sum512_224(b: &[u8]) -> [u8; SIZE224] {
    let d = Sha512Trunc224::digest(b);

    let mut out = [0u8; SIZE224];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}

pub fn sum512_256(b: &[u8]) -> [u8; SIZE256] {
    let d = Sha512Trunc256::digest(b);

    let mut out = [0u8; SIZE256];
    (&mut out[..]).copy_from_slice(d.as_slice());

    out
}
