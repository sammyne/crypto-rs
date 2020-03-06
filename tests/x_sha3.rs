//#[cfg(test)]
#[cfg(all(test, feature = "sha3"))]
mod test {
    use cryptographer::x::sha3::{
        self, Hash, Keccak256, Keccak512, SHA3_224, SHA3_256, SHA3_384, SHA3_512,
    };
    use encoding::hex;
    use serde_json::{self, Value};
    use std::fs;
    use std::io::{Read, Write};

    #[test]
    fn keccak256() {
        // in form of (msg, digest)
        let test_cases = vec![(
            b"abc",
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )];

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::keccak256(msg);
                hex::encode_to_string(&md[..])
            };

            assert_eq!(&got, expect);
        }
    }

    #[test]
    fn keccak512() {
        // in form of (msg, digest)
        let test_cases = vec![(
        b"abc",
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
    )];

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::keccak512(msg);
                hex::encode_to_string(&md[..])
            };

            assert_eq!(&got, expect);
        }
    }

    #[test]
    fn new_legacy_keccak256() {
        let mut h = Keccak256::new();

        let hello = b"abc";
        h.write(hello).expect("failed to consume 'hello'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
        assert_eq!(&got, expect);
    }

    #[test]
    fn new_legacy_keccak512() {
        let mut h = Keccak512::new();

        let hello = b"abc";
        h.write(hello).expect("failed to consume 'hello'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha224() {
        let mut h = SHA3_224::new();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "c4797897c58a0640df9c4e9a8f30570364d9ed8450c78ed155278ac0";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha256() {
        let mut h = SHA3_256::new();

        let hello = "hello".as_bytes();
        h.write(&hello).expect("failed to consume 'hello'");

        let world = "world".as_bytes();
        h.write(&world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "92dad9443e4dd6d70a7f11872101ebff87e21798e4fbb26fa4bf590eb440e71b";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha384() {
        let mut h = SHA3_384::new();

        let hello = b"hello";
        h.write(hello).expect("failed to consume 'hello'");

        let world = b"world";
        h.write(world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "dc6104dc2caff3ce2ccecbc927463fc3241c8531901449f1b1f4787394c9b3aa55a9e201d0bb0b1b7d7f8892bc127216";
        assert_eq!(&got, expect);
    }

    #[test]
    fn sha512() {
        let mut h = SHA3_512::new();

        let hello = b"hello";
        h.write(hello).expect("failed to consume 'hello'");

        let world = b"world";
        h.write(world).expect("failed to consume 'world'");

        let d = h.sum();
        let got = hex::encode_to_string(&d[..]);

        let expect = "938315ec7b0e0bcac648ae6f732f67e00f9c6caa3991627953434a0769b0bbb15474a429177013ed8a7e48990887d1e19533687ed2183fd2b6054c2e8828ca1c";
        assert_eq!(&got, expect);
    }

    #[test]
    fn shake128() {
        let mut h = sha3::new_shake128();

        let hello = b"hello";
        h.write(hello).expect("failed to consume 'hello'");

        let world = b"world";
        h.write(world).expect("failed to consume 'world'");

        let mut d = vec![0u8; 32];

        h.read(d.as_mut_slice()).expect("unfallible");
        let got = hex::encode_to_string(d.as_slice());

        let expect = "c10fb3319e7b048b84ed8ead46abbb9f2305f595ced48174125064d734a07a3a";
        assert_eq!(&got, expect);

        h.read(d.as_mut_slice()).expect("unfallible");
        let got = hex::encode_to_string(d.as_slice());

        let expect = "b07997518d5a3443f9474c203b8762ab955eb8b1b6e19eb9e871b07f89f2e7f3";
        assert_eq!(&got, expect);
    }

    #[test]
    fn shake256() {
        let mut h = sha3::new_shake256();

        let hello = b"hello";
        h.write(hello).expect("failed to consume 'hello'");

        let world = b"world";
        h.write(world).expect("failed to consume 'world'");

        let mut d = vec![0u8; 32];

        h.read(d.as_mut_slice()).expect("unfallible");
        let got = hex::encode_to_string(d.as_slice());

        let expect = "0599df850188c1933b38dc74b7e6972bc054234f01cd7f9e8e2e8cc40acb149d";
        assert_eq!(&got, expect);

        h.read(d.as_mut_slice()).expect("unfallible");
        let got = hex::encode_to_string(d.as_slice());

        let expect = "894d9b3d8149cafe7ff89526576c7d8626424a83c82522d4b8120fceca7f7319";
        assert_eq!(&got, expect);
    }

    #[test]
    fn shake_sum128() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/shake128.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let mut md = [0u8; 512];
                sha3::shake_sum128(&mut md[..], msg.as_slice()).expect("unfallible");
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }

    #[test]
    fn shake_sum256() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/shake256.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let mut md = [0u8; 512];
                sha3::shake_sum256(&mut md[..], msg.as_slice()).expect("unfallible");
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }

    #[test]
    fn sum224() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/sha3-224.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::sum224(msg.as_slice());
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }

    #[test]
    fn sum256() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/sha3-256.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::sum256(msg.as_slice());
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }

    #[test]
    fn sum384() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/sha3-384.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::sum384(msg.as_slice());
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }

    #[test]
    fn sum512() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/sha3/sha3-512.json"
        };

        let testdata = fs::read_to_string(testdata_path).expect("failed to load testdata");
        let raw_test_cases: Vec<Value> = match serde_json::from_str(&testdata) {
            Ok(v) => v,
            _ => panic!("expecting array"),
        };

        let test_cases = raw_test_cases.iter().map(|v| {
            let ell = match &v["length"] {
                Value::Number(v) => v.as_u64().expect("non-integral length"),
                _ => panic!("non-integral length"),
            };

            let msg = if ell != 0 {
                hex::decode_string(v["message"].as_str().expect("missing 'message'"))
                    .expect("invalid hex string")
            } else {
                vec![]
            };

            (msg, v["digest"].as_str().expect("missing 'digest'"))
        });

        for v in test_cases {
            let (msg, expect) = (v.0, v.1);

            let got = {
                let md = sha3::sum512(msg.as_slice());
                hex::encode_to_string(&md[..])
            };

            assert_eq!(expect.to_ascii_lowercase(), got);
        }
    }
}
