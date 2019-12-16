use std::io::Write;
use cryptographer::sha256::{self, Hash, SHA224, SHA256};
use encoding::hex;

#[test]
fn sha256_sha224() {
    let mut h = SHA224::new();

    let hello = "hello".as_bytes();
    h.write(&hello).expect("failed to consume 'hello'");

    let world = "world".as_bytes();
    h.write(&world).expect("failed to consume 'world'");

    let d = h.sum();
    let got = hex::encode_to_string(&d[..]);

    let expect = "b033d770602994efa135c5248af300d81567ad5b59cec4bccbf15bcc";
    assert_eq!(&got, expect);
}

#[test]
fn sha256_sha256() {
    let mut h = SHA256::new();

    let hello = "hello".as_bytes();
    h.write(&hello).expect("failed to consume 'hello'");

    let world = "world".as_bytes();
    h.write(&world).expect("failed to consume 'world'");

    let d = h.sum();
    let got = hex::encode_to_string(&d[..]);

    let expect = "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
    assert_eq!(&got, expect);
}

#[test]
fn sum224() {
    let test_cases = vec![
        (
            "hello".as_bytes(),
            "ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193",
        ),
        (
            "world".as_bytes(),
            "06d2dbdb71973e31e4f1df3d7001fa7de268aa72fcb1f6f9ea37e0e5",
        ),
    ];

    for v in test_cases.iter() {
        let (msg, expect) = v;

        let digest = sha256::sum224(msg);
        let got = hex::encode_to_string(&digest[..]);

        assert_eq!(*expect, &got);
    }
}

#[test]
fn sum256() {
    let test_cases = vec![
        (
            "hello".as_bytes(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        ),
        (
            "world".as_bytes(),
            "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7",
        ),
    ];

    for v in test_cases.iter() {
        let (msg, expect) = v;

        let digest = sha256::sum256(msg);
        let got = hex::encode_to_string(&digest[..]);

        assert_eq!(*expect, &got);
    }
}
