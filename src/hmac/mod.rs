//! module hmac implements the Keyed-Hash Message Authentication Code (HMAC) as defined in U.S.
//! Federal Information Processing Standards Publication 198. An HMAC is a cryptographic hash that
//! uses a key to sign a message. The receiver verifies the hash by recomputing it using the same
//! key.

use std::io::{self, Write};

pub use super::Hash;

/// HMAC implements the Keyed-Hash Message Authentication Code defined as FIPS-198.
/// @TODO: implement default generic type for H
pub struct HMAC<H>
where
    H: Hash,
{
    inner: H,
    ipad: Vec<u8>,
    opad: Vec<u8>,
    outer: H,
}

impl<H> Hash for HMAC<H>
where
    H: Hash,
{
    fn size() -> usize {
        H::size()
    }

    fn block_size() -> usize {
        H::block_size()
    }

    fn reset(&mut self) {
        self.inner.reset();
        let _ = self.inner.write(self.ipad.as_slice());
    }

    fn sum(&mut self) -> Vec<u8> {
        let inhash = self.inner.sum();

        self.outer.reset();
        let _ = self.outer.write(&self.opad);
        let _ = self.outer.write(inhash.as_slice());

        self.outer.sum()
    }
}

impl<H> Write for HMAC<H>
where
    H: Hash,
{
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
}

/// new returns a new HMAC hash using the given Hash type as generic parameter H and
/// key.
pub fn new<H, F>(new_hash: F, key: &[u8]) -> HMAC<H>
where
    H: Hash,
    F: Fn() -> H,
{
    let mut outer = new_hash();
    let mut inner = new_hash();

    let key = if key.len() > H::block_size() {
        let _ = outer.write(key);
        outer.sum()
    } else {
        let mut k = key.to_vec();
        k.resize(H::block_size(), 0);

        k
    };

    let mut ipad = key.clone();
    let mut opad = key.clone();

    for v in &mut ipad {
        *v ^= 0x36;
    }
    for v in &mut opad {
        *v ^= 0x5c;
    }

    let _ = inner.write(ipad.as_slice());

    HMAC {
        inner,
        ipad,
        opad,
        outer,
    }
}

/// sum calculates the HMAC for given data based on given key, where the hash function to use is
/// specified by means of generic parameter H
pub fn sum<H, F>(new_hash: F, key: &[u8], data: &[u8]) -> Vec<u8>
where
    H: Hash,
    F: Fn() -> H,
{
    let mut h = new(new_hash, key);

    let _ = h.write(data);
    h.sum()
}
