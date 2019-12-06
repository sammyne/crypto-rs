pub use digest::Digest;

pub trait Hash {
    fn block_size() -> usize;
    fn new() -> Self;
    fn size() -> usize;

    fn reset(&mut self);
    fn sum(&self) -> Vec<u8>;
    fn write(&mut self, buf: &[u8]) -> Result<usize, String>;
}
