//! module subtle implements functions that are often useful in cryptographic code but require
//! careful thought to use correctly.

/// constant_time_byte_eq returns 1 if x == y and 0 otherwise.
pub fn constant_time_byte_eq(x: u8, y: u8) -> isize {
    (((x ^ y) as u32).wrapping_sub(1) >> 31) as isize
}

/// constant_time_compare returns 1 if the two slices, x and y, have equal contents and 0
/// otherwise. The time taken is a function of the length of the slices and is independent of the
/// contents.
pub fn constant_time_compare(x: &[u8], y: &[u8]) -> isize {
    if x.len() != y.len() {
        return 0;
    }

    let mut v = 0u8;
    for i in 0..x.len() {
        v |= x[i] ^ y[i];
    }

    constant_time_byte_eq(v, 0)
}

/// constant_time_copy copies the contents of y into x (a slice of equal length) if v == 1. If v ==
/// 0, x is left unchanged. Its behavior is undefined if v takes any other value.
pub fn constant_time_copy(v: isize, x: &mut [u8], y: &[u8]) {
    if x.len() != y.len() {
        panic!("subtle: slices have different lengths");
    }

    let xmask = (v - 1) as u8;
    let ymask = !(v - 1) as u8;
    for i in 0..x.len() {
        x[i] = x[i] & xmask | y[i] & ymask;
    }
}

/// constant_time_eq returns 1 if x == y and 0 otherwise.
pub fn constant_time_eq(x: i32, y: i32) -> isize {
    (((x ^ y) as u32 - 1) as u64 >> 63) as isize
}

/// constant_time_less_or_eq returns 1 if x <= y and 0 otherwise. Its behavior is undefined if x or
/// y are negative or > 2**31 - 1.
pub fn constant_time_less_or_eq(x: isize, y: isize) -> isize {
    let (x32, y32) = (x as i32, y as i32);
    (((x32 - y32).wrapping_sub(1) >> 31) & 1) as isize
}

/// constant_time_select returns x if v == 1 and y if v == 0. Its behavior is undefined if v takes
/// any other value.
pub fn constant_time_select(v: isize, x: isize, y: isize) -> isize {
    !(v - 1) & x | (v - 1) & y
}
