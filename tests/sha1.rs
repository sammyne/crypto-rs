#[cfg(all(test, feature = "sha1"))]
mod test {
    use cryptographer::sha1;
    use encoding::hex;

    #[test]
    fn sum() {
        // in form of (msg, expected hash)
        let test_vector = vec![(
            "This page intentionally left blank.",
            "af064923bbf2301596aac4c273ba32178ebc4a96",
        )];

        for c in test_vector {
            let (msg, expect) = c;
            let got = {
                let v = sha1::sum(msg.as_bytes());
                hex::encode_to_string(&v[..])
            };

            assert_eq!(&got, expect);
        }
    }
}
