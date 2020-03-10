use cryptographer::hmac::{self, Hash};
use cryptographer::sha256;
use encoding::hex;
use std::io::Write;

#[test]
fn hmac_sha256() {
    let key = "hello".as_bytes();
    //let mut h = hmac::new::<SHA256>(&key);
    let mut h = hmac::new(sha256::new, &key);

    let world = "world".as_bytes();
    h.write(&world).expect("failed to consume 'world'");

    let how_do_you_do = "how do you do".as_bytes();
    h.write(&how_do_you_do)
        .expect("failed to consume 'how_do_you_do'");

    let d = h.sum();
    let got = hex::encode_to_string(&d[..]);

    let expect = "a6a247ab2f6e7f4487996f18bb8290a7829a21cc8e79bb129e8451bf97e14f6d";
    assert_eq!(&got, expect);
}

#[test]
fn sum_sha256() {
    // in form of (key, data, expect)
    let test_cases = vec![(
        "my secret and secure key".as_bytes(),
        "input message".as_bytes(),
        "97d2a569059bbcd8ead4444ff99071f4c01d005bcefe0d3567e1be628e5fdcd9",
    )];

    for v in test_cases.iter() {
        let (key, data, expect) = v;

        let digest = hmac::sum(sha256::new, key, data);
        let got = hex::encode_to_string(&digest[..]);

        assert_eq!(*expect, &got);
    }
}
