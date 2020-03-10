#[cfg(all(test, feature = "sha512"))]
mod test {
    use std::io::Write;

    use encoding::hex;

    use cryptographer::sha512::{self, Hash};

    #[test]
    fn sha384() {
        let mut h = sha512::new384();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "97982a5b1414b9078103a1c008c4e3526c27b41cdbcf80790560a40f2a9bf2ed4427ab1428789915ed4b3dc07c454bd9";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha512() {
        let mut h = sha512::new();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "1594244d52f2d8c12b142bb61f47bc2eaf503d6d9ca8480cae9fcf112f66e4967dc5e8fa98285e36db8af1b8ffa8b84cb15e0fbcf836c3deb803c13f37659a60";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha512_224() {
        let mut h = sha512::new512_224();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "f66507e2077a88702bd3890f0e081184fba63530f0300b9fea50691a";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha512_256() {
        let mut h = sha512::new512_256();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "a716e87c54064789b75127f426e9fb7086d78a3026e7e02efcce6126a37505ae";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sum384() {
        let test_cases = vec![
        (
            "hello".as_bytes(),
            "59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f",
        ),
        (
            "world".as_bytes(),
            "a4d102bb2a39b6f1d9e481ef1a16b8948a0df2b594fd031bad6f201fbd6b0656846a6e58a30aa57ff34d912e7d3ea185",
        ),
    ];

        for v in test_cases.iter() {
            let (msg, expect) = v;

            let digest = sha512::sum384(msg);
            let got = hex::encode_to_string(&digest[..]);

            assert_eq!(*expect, &got);
        }
    }

    #[test]
    fn sum512() {
        let test_cases = vec![
        (
            "hello".as_bytes(),
            "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043",
        ),
        (
            "world".as_bytes(),
            "11853df40f4b2b919d3815f64792e58d08663767a494bcbb38c0b2389d9140bbb170281b4a847be7757bde12c9cd0054ce3652d0ad3a1a0c92babb69798246ee",
        ),
    ];

        for v in test_cases.iter() {
            let (msg, expect) = v;

            let digest = sha512::sum512(msg);
            let got = hex::encode_to_string(&digest[..]);

            assert_eq!(*expect, &got);
        }
    }

    #[test]
    fn sum512_224() {
        let test_cases = vec![
            (
                "hello".as_bytes(),
                "fe8509ed1fb7dcefc27e6ac1a80eddbec4cb3d2c6fe565244374061c",
            ),
            (
                "world".as_bytes(),
                "4fc187a8ac275771f3f5d4ea04ba2b1460874a720c63d96cc4d043c1",
            ),
        ];

        for v in test_cases.iter() {
            let (msg, expect) = v;

            let digest = sha512::sum512_224(msg);
            let got = hex::encode_to_string(&digest[..]);

            assert_eq!(*expect, &got);
        }
    }

    #[test]
    fn sum512_256() {
        let test_cases = vec![
            (
                "hello".as_bytes(),
                "e30d87cfa2a75db545eac4d61baf970366a8357c7f72fa95b52d0accb698f13a",
            ),
            (
                "world".as_bytes(),
                "b8007fc640bef3e2f10ea7ad9681f6fdbd132887406960f365452ba0a15e65e2",
            ),
        ];

        for v in test_cases.iter() {
            let (msg, expect) = v;

            let digest = sha512::sum512_256(msg);
            let got = hex::encode_to_string(&digest[..]);

            assert_eq!(*expect, &got);
        }
    }
}
