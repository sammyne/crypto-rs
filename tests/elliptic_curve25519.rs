#[cfg(all(test, feature = "curve25519"))]
mod test {
    use cryptographer::elliptic::curve25519;
    use encoding::hex;

    fn decode_hexstr_as_array32(s: &str) -> [u8; 32] {
        let a = hex::decode_string(s).expect("hex decoding failed");
        let mut out = [0u8; 32];
        (&mut out).copy_from_slice(&a);

        out
    }

    #[test]
    fn scalar_mult() {
        // tese case is of form (scalar, point, expect_output)
        let test_cases = vec![
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];

        for v in test_cases.iter() {
            let scalar = decode_hexstr_as_array32(v.0);
            let point = decode_hexstr_as_array32(v.1);
            let expect = v.2;

            let got = {
                let got = curve25519::scalar_mult(scalar, point);
                hex::encode_to_string(&got)
            };

            assert_eq!(expect, &got);
        }
    }

    #[test]
    fn scalar_mult_base() {
        // test case in form of (scalar, expect_output)
        let test_vector = vec![
            (
                "d084c7bc9a3f6468d2b9817f2f0eea18c17175d8deabbcd0a34d039d1ca813b2",
                "5cf07692756426ba39cf9f97d1f87cc440dbb18829bb20858166f8f210853e02",
            ),
            (
                "9ac1356a61715653b36cc525f3569a5a0b39b645798e86e408df64c3c5aecc23",
                "8015538b687e5e3e6c890412c60ca5ae9d1bd10210f9ebb7a6a1c3eaa3ab853d",
            ),
            (
                "d6bcdc444347a06811dbc3abc62773f7d85148163945944467403a9e102d225c",
                "a0fa79a9ad8b4e00d1c76aca83be6b4da7c49757cb755dfd7dbcfd8782625d00",
            ),
            (
                "9b7d9fdb92b8fe22efbcbeb43c09865b5248e6fee017e86078395f4ef924117b",
                "45a233a00de4e7ec4b3b2bafddab4d92c4276c238a0ef31aa82ff8f3fe99e27d",
            ),
            (
                "4aa543c32ec9ab294e51902e613ee91e57756fcebf9ae549bf5a3337c73f2868",
                "2cde8058bd8fab39a9f31bb7fcda71f8c9f9bd189cd79073bdd4744f09eb7d30",
            ),
            (
                "1c7515955ea5f7c5e2b94cb8d20cfd975e78b0ccf57ed41dcbc57d23c8a311a0",
                "36287fb7cebd6909b1d00ba704120239dad85bdccd3bc1fca10fb4cf1a97ee4b",
            ),
            (
                "72c779ebae5aa6aab8f902db94ef0e3057604ed3f886239255183203dd63d1f3",
                "efe96b226350972074b4918eeba6c2f0603c02f73adfc0940fa74fa626e45d49",
            ),
            (
                "3c7c51264a79cec58b075326674726b6f5e1ca069f0427cad2420864e37d4a33",
                "57c75bcfb05ef22e6336182fbaa92c5288590643ab361b3b1dc4c9ba8d0fff7c",
            ),
        ];

        for v in test_vector.iter() {
            let scalar = decode_hexstr_as_array32(v.0);
            let expect = v.1;

            let got = {
                let got = curve25519::scalar_base_mult(scalar);
                hex::encode_to_string(&got)
            };

            assert_eq!(expect, &got);
        }
    }

    #[test]
    fn x25519() {
        // tese case is of form (scalar, point, expect_output)
        let test_cases = vec![
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];

        for v in test_cases.iter() {
            let scalar = decode_hexstr_as_array32(v.0);
            let point = decode_hexstr_as_array32(v.1);
            let expect = v.2;

            let got = {
                let got = curve25519::x25519(scalar, point);
                hex::encode_to_string(&got)
            };

            assert_eq!(expect, &got);
        }
    }
}
