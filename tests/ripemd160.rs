#[cfg(all(test, feature = "ripemd160"))]
mod test {
    use std::io::Write;

    use cryptographer::x::ripemd160::{self, Hash};
    use encoding::hex;

    #[test]
    fn ripemd160() {
        let mut h = ripemd160::new();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "8a73c5438c28e79e696144fa869886f240cfaddb";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sum() {
        let test_cases = vec![
            (
                "hello".as_bytes(),
                "108f07b8382412612c048d07d13f814118445acd",
            ),
            (
                "world".as_bytes(),
                "dbd32a04286f48676f2308fbcf30cc3202286de7",
            ),
        ];

        for v in test_cases.iter() {
            let (msg, expect) = v;

            let digest = ripemd160::sum(msg);
            let got = hex::encode_to_string(&digest[..]);

            assert_eq!(*expect, &got);
        }
    }
}
