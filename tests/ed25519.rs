#[cfg(all(test, feature = "ed25519"))]
mod test {
    use std::convert::TryFrom;
    use std::fs::File;
    use std::io::prelude::*;
    use std::io::BufReader;

    use cryptographer::ed25519::{self, PublicKey, PRIVATE_KEY_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN};
    use cryptographer::rand::Rand;
    use cryptographer::Signer;

    use encoding::hex;

    #[test]
    fn crypto_signer() {
        let rand = [0u8; PRIVATE_KEY_LEN - PUBLIC_KEY_LEN];

        let (priv_key, pub_key) = ed25519::generate_key(&mut &rand[..]).unwrap();

        let msg = "hello world".as_bytes();
        let sig = priv_key.sign(&mut &rand[..], &msg).expect("failed to sign");

        ed25519::verify(&pub_key, &msg, &sig).expect("verification failed");
    }

    #[test]
    fn golden() {
        let testdata_path = {
            let root =
                std::env::var("CARGO_MANIFEST_DIR").expect("failed read 'CARGO_MANIFEST_DIR'");
            root + "/testdata/ed25519/sign.input.txt"
        };

        let reader = {
            let f = File::open(testdata_path).expect("failed to read in testdata");
            BufReader::new(f)
        };

        for (i, line) in reader.lines().enumerate() {
            let line = line.unwrap();

            let parts: Vec<&str> = line.split(":").collect();
            if parts.len() != 5 {
                panic!("bad number of parts on line {}", i);
            }

            let (priv_key, _) = match hex::decode_string(parts[0]) {
                Ok(v) => ed25519::generate_key(&mut v.as_slice())
                    .map_err(|_| panic!("failed to unmarshal private key at line: {}", i))
                    .unwrap(),
                _ => panic!("failed to decode private key at line: {}", i),
            };
            let pub_key = match hex::decode_string(parts[1]) {
                Ok(v) => PublicKey::try_from(v.as_slice())
                    .map_err(|_| panic!("failed to unmarshal public key at line: {}", i))
                    .unwrap(),
                _ => panic!("failed to decode public key at line: {}", i),
            };
            let msg = match hex::decode_string(parts[2]) {
                Ok(v) => v,
                _ => panic!("failed to decode msg at line: {}", i),
            };
            // The signatures in the test vectors also include the message
            // at the end, but we just want R and S.
            let sig = match hex::decode_string(parts[3]) {
                Ok(mut v) => {
                    v.resize(SIGNATURE_LEN, 0);
                    v
                }
                _ => panic!("failed to decode sig at line: {}", i),
            };

            let sig2 = ed25519::sign(&priv_key, &msg);
            if sig2 != sig {
                panic!(
                    "mismatch sig at line {}, expect {:x?}, got {:x?}",
                    i, &sig, &sig2
                );
            }

            if let Err(err) = ed25519::verify(&pub_key, &msg, &sig) {
                panic!("verification failed at line {}: {:?}", i, err);
            }

            if priv_key.public() != pub_key {
                panic!(
                    "mismatch public key at line {}, got {:?}, expect {:?}",
                    i,
                    priv_key.public(),
                    &pub_key,
                );
            }
        }
    }

    #[test]
    fn malleability() {
        let msg: [u8; 4] = [0x54, 0x65, 0x73, 0x74];
        let sig: [u8; 64] = [
            0x7c, 0x38, 0xe0, 0x26, 0xf2, 0x9e, 0x14, 0xaa, 0xbd, 0x05, 0x9a, 0x0f, 0x2d, 0xb8,
            0xb0, 0xcd, 0x78, 0x30, 0x40, 0x60, 0x9a, 0x8b, 0xe6, 0x84, 0xdb, 0x12, 0xf8, 0x2a,
            0x27, 0x77, 0x4a, 0xb0, 0x67, 0x65, 0x4b, 0xce, 0x38, 0x32, 0xc2, 0xd7, 0x6f, 0x8f,
            0x6f, 0x5d, 0xaf, 0xc0, 0x8d, 0x93, 0x39, 0xd4, 0xee, 0xf6, 0x76, 0x57, 0x33, 0x36,
            0xa5, 0xc5, 0x1e, 0xb6, 0xf9, 0x46, 0xb3, 0x1d,
        ];
        let raw_pub_key: [u8; PUBLIC_KEY_LEN] = [
            0x7d, 0x4d, 0x0e, 0x7f, 0x61, 0x53, 0xa6, 0x9b, 0x62, 0x42, 0xb5, 0x22, 0xab, 0xbe,
            0xe6, 0x85, 0xfd, 0xa4, 0x42, 0x0f, 0x88, 0x34, 0xb1, 0x08, 0xc3, 0xbd, 0xae, 0x36,
            0x9e, 0xf5, 0x49, 0xfa,
        ];

        let pub_key =
            PublicKey::try_from(&raw_pub_key[..]).expect("failed to unmarshal public key");

        if let Ok(_) = ed25519::verify(&pub_key, &msg, &sig) {
            panic!("verification failed")
        }
    }

    #[test]
    fn sign_verify() {
        let mut rand = Rand::new();

        let (priv_key, pub_key) = ed25519::generate_key(&mut rand).unwrap();

        let msg = "hello world".as_bytes();

        let sig = ed25519::sign(&priv_key, &msg);

        ed25519::verify(&pub_key, &msg, &sig).unwrap();
    }
}
