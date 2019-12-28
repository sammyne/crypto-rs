//! module cipher implements standard block cipher modes that can be wrapped around low-level block
//! cipher implementations. See [https://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html][1]
//! and NIST Special Publication 800-38A
//!
//! [1]: https://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html

/// A Block represents an implementation of block cipher using a given key. It provides the
/// capability to encrypt or decrypt individual blocks. The mode implementations extend that
/// capability to streams of blocks.
pub trait Block {
    /// block_size returns the cipher's block size.
    fn block_size(&self) -> usize;

    // encrypt encrypts the first block in src into dst.
    // Dst and src must overlap entirely or not at all.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]);

    // decrypt decrypts the first block in src into dst.
    // Dst and src must overlap entirely or not at all.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]);
}
