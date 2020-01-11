use cryptographer::subtle;

fn random_bytes() -> (Vec<u8>, Vec<u8>) {
    let ell = (rand::random::<u8>() as usize) + 1;

    let mut x = vec![0u8; ell];
    for v in &mut x {
        *v = rand::random();
    }

    let mut y = vec![0u8; ell];
    for v in &mut y {
        *v = rand::random();
    }

    // ensure y!=x
    y[0] = x[0].wrapping_add(1);

    (x, y)
}

#[test]
fn constant_time_byte_eq() {
    // in form of (x, y, expect)
    let test_vector = vec![
        (0u8, 0u8, 1),
        (0, 1, 0),
        (1, 0, 0),
        (0xff, 0xff, 1),
        (0xff, 0xfe, 0),
    ];

    for v in test_vector {
        let (x, y, expect) = v;

        let got = subtle::constant_time_byte_eq(x, y);
        assert_eq!(expect, got, "failed for {} vs {}", x, y);
    }

    const DEFAULT_MAX_COUNT: usize = 100;
    // more random test vector
    for _i in 0..DEFAULT_MAX_COUNT {
        let x: u8 = rand::random();
        let y: u8 = rand::random();

        let expect = if x == y { 1 } else { 0 };
        let got = subtle::constant_time_byte_eq(x, y);
        assert_eq!(expect, got, "failed for {} vs {}", x, y);
    }
}

#[test]
fn constant_time_compare() {
    // in form of (x, y, expect)
    let test_vector = vec![
        (Vec::new(), Vec::new(), 1isize),
        (vec![0x11], vec![0x11], 1),
        (vec![0x12], vec![0x11], 0),
        (vec![0x11], vec![0x11, 0x12], 0),
        (vec![0x11, 0x12], vec![0x11], 0),
    ];

    for (i, v) in test_vector.iter().enumerate() {
        let (x, y, expect) = v;
        let got = subtle::constant_time_compare(x.as_slice(), y.as_slice());

        assert_eq!(*expect, got, "[{}] failed for {:?} vs {:?}", i, x, y);
    }
}

#[test]
fn constant_time_copy() {
    const DEFAULT_MAX_COUNT: usize = 100;

    for _i in 0..DEFAULT_MAX_COUNT {
        let (x, y) = random_bytes();
        let mut xx = x.clone();

        subtle::constant_time_copy(0, xx.as_mut_slice(), y.as_slice());
        assert_eq!(xx, x);

        subtle::constant_time_copy(1, xx.as_mut_slice(), y.as_slice());
        assert_ne!(xx, x);
    }
}

#[test]
fn constant_time_eq() {
    const DEFAULT_MAX_COUNT: usize = 100;

    for _i in 0..DEFAULT_MAX_COUNT {
        let x: i32 = rand::random();
        let y: i32 = rand::random();

        let expect = if x == y { 1 } else { 0 };

        assert_eq!(expect, subtle::constant_time_eq(x, y));
    }
}

#[test]
fn constant_time_less_or_eq() {
    // in form of (x, y, expect)
    let test_vector = vec![
        (0isize, 0isize, 1isize),
        (1, 0, 0),
        (0, 1, 1),
        (10, 20, 1),
        (20, 10, 0),
        (10, 10, 1),
    ];

    for (i, v) in test_vector.iter().enumerate() {
        let (x, y, expect) = *v;
        let got = subtle::constant_time_less_or_eq(x, y);

        assert_eq!(expect, got, "[{}] failed for {:?} vs {:?}", i, x, y);
    }
}
