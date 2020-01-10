//! module subtle implements functions that are often useful in cryptographic
//! code but require careful thought to use correctly.

/// any_overlap reports whether x and y share memory at any (not necessarily
/// corresponding) index. The memory beyond the slice length is ignored.
pub fn any_overlap(x: &[u8], y: &[u8]) -> bool {
    x.len() > 0
        && y.len() > 0
        && unsafe {
            (x.as_ptr() <= y.as_ptr().offset(y.len() as isize - 1))
                && (y.as_ptr() <= x.as_ptr().offset(x.len() as isize - 1))
        }
}

/// inexact_overlap reports whether x and y share memory at any non-corresponding
/// index. The memory beyond the slice length is ignored. Note that x and y can
/// have different lengths and still not have any inexact overlap.
//
/// inexact_overlap can be used to implement the requirements of the crypto/cipher
/// AEAD, Block, BlockMode and Stream interfaces.
pub fn inexact_overlap(x: &[u8], y: &[u8]) -> bool {
    !(x.len() == 0 || y.len() == 0 || x.as_ptr() == y.as_ptr()) && any_overlap(x, y)
}
