use std::io::Write;

/// The `Hash` trait specifies the common interface for hash functions.
///
/// The `write` from `Write` trait adds more data to the running hash.
/// It never returns an error.
pub trait Hash: Write {
    /// block_size returns the hash's underlying block size.
    /// The Write method must be able to accept any amount
    /// of data, but it may operate more efficiently if all writes
    /// are a multiple of the block size.
    fn block_size() -> usize;
    /// new creates a fresh hasher instance
    //fn new() -> Self;
    /// size returns the number of bytes Sum will return
    fn size() -> usize;

    /// reset resets the Hash to its initial state
    fn reset(&mut self);
    /// sum returns the resulting slice. It does not change the underlying hash state.
    fn sum(&mut self) -> Vec<u8>;
}
