// @TODO more tests are needed

pub fn constant_time_byte_eq(x: u8, y: u8) -> isize {
    (((x ^ y) as u32).wrapping_sub(1) >> 31) as isize
}

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

pub fn constant_time_eq(x: i32, y: i32) -> isize {
    (((x ^ y) as u32 - 1) as u64 >> 63) as isize
}

pub fn constant_time_less_or_eq(x: isize, y: isize) -> isize {
    let (x32, y32) = (x as i32, y as i32);
    (((x32 - y32).wrapping_sub(1) >> 31) & 1) as isize
}

pub fn constant_time_select(v: isize, x: isize, y: isize) -> isize {
    !(v - 1) & x | (v - 1) & y
}
