#[cfg(all(test, feature = "aes"))]
mod test {
    use cryptographer::aes::{self, Block};
    use encoding::hex;

    #[test]
    fn aes128() {
        let key: [u8; 16] = [
            241, 64, 92, 237, 139, 153, 104, 186, 249, 16, 146, 89, 81, 91, 247, 2,
        ];

        let plaintext = "hello world to u".as_bytes();
        let mut ciphertext = [0u8; 16];

        let c = aes::new_cipher(&key).expect("failed to new cipher");

        // encrypt and compare
        c.encrypt(&mut ciphertext, &plaintext);
        let got = hex::encode_to_string(&ciphertext[..]);
        let expect = "8e6baedffef52884db57dfca0028054a";
        assert_eq!(expect, &got);

        // decrypt and compare
        let mut recovered = [0u8; 16];
        c.decrypt(&mut recovered, &ciphertext);
        assert_eq!(&recovered, &plaintext);
    }

    #[test]
    fn aes192() {
        const BLOCK_LEN: usize = 16;

        let key: [u8; 24] = [
            241, 64, 92, 237, 139, 153, 104, 186, 249, 16, 146, 89, 81, 91, 247, 2, 90, 41, 27, 0,
            255, 123, 253, 106,
        ];

        let plaintext = "hello world to u".as_bytes();
        let mut ciphertext = [0u8; BLOCK_LEN];

        let c = aes::new_cipher(&key).expect("failed to new cipher");

        // encrypt and compare
        c.encrypt(&mut ciphertext, &plaintext);
        let got = hex::encode_to_string(&ciphertext[..]);
        let expect = "43608085ca4b8763e4fc84adbceb82c7";
        assert_eq!(expect, &got);

        // decrypt and compare
        let mut recovered = [0u8; BLOCK_LEN];
        c.decrypt(&mut recovered, &ciphertext);
        assert_eq!(&recovered, &plaintext);
    }

    #[test]
    fn aes256() {
        const BLOCK_LEN: usize = 16;

        let key: [u8; 32] = [
            241, 64, 92, 237, 139, 153, 104, 186, 249, 16, 146, 89, 81, 91, 247, 2, 90, 41, 27, 0,
            255, 123, 253, 106, 76, 219, 81, 212, 15, 75, 54, 124,
        ];

        let plaintext = "hello world to u".as_bytes();
        let mut ciphertext = [0u8; BLOCK_LEN];

        let c = aes::new_cipher(&key).expect("failed to new cipher");

        // encrypt and compare
        c.encrypt(&mut ciphertext, &plaintext);
        let got = hex::encode_to_string(&ciphertext[..]);
        let expect = "7024f3b668c638fd9ba37032c079a595";
        assert_eq!(expect, &got);

        // decrypt and compare
        let mut recovered = [0u8; BLOCK_LEN];
        c.decrypt(&mut recovered, &ciphertext);
        assert_eq!(&recovered, &plaintext);
    }
}
