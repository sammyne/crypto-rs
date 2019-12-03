use std::io;

use rand::{rngs::OsRng, RngCore};

pub struct Rand(OsRng);

impl Rand {
    pub fn new() -> Self {
        Rand(OsRng::default())
    }
}

impl io::Read for Rand {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.0.try_fill_bytes(buf)?;

        Ok(buf.len())
    }
}
