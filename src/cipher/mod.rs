/// A Block represents an implementation of block cipher using a given key. It provides the capability to encrypt or decrypt individual blocks. The mode implementations extend that capability to streams of blocks.
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
