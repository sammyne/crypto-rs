use std::io::Write;

use cryptographer::md5::{self, Hash};
use encoding::hex;

#[test]
fn md5() {
    let mut h = md5::new();

    let hello = "hello".as_bytes();
    h.write(&hello).expect("failed to consume 'hello'");

    let world = "world".as_bytes();
    h.write(&world).expect("failed to consume 'world'");

    let d = h.sum();
    let got = hex::encode_to_string(&d[..]);

    let expect = "fc5e038d38a57032085441e7fe7010b0";
    assert_eq!(&got, expect);
}

#[test]
fn sum() {
    let test_cases = vec![
        ("hello".as_bytes(), "5d41402abc4b2a76b9719d911017c592"),
        ("world".as_bytes(), "7d793037a0760186574b0282f2f435e7"),
    ];

    for v in test_cases.iter() {
        let (msg, expect) = v;

        let digest = md5::sum(msg);
        let got = hex::encode_to_string(&digest[..]);

        assert_eq!(*expect, &got);
    }
}
