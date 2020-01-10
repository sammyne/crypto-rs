use cryptographer::subtle;

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

    for (i, v) in test_vector.iter().enumerate() {
        let (x, y, expect) = *v;

        let got = subtle::constant_time_byte_eq(x, y);
        assert_eq!(expect, got, "#{} failed for {} vs {}", i, x, y);
    }

    // add on the quick.CheckEqual
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
