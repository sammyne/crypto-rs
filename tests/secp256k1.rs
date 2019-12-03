use cryptographer::{secp256k1, PrivateKey};

#[test]
fn sign_verify() {
    let mut rand = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin cursus enim at leo venenatis commodo. Morbi et luctus lectus. Vestibulum interdum nulla pulvinar, egestas purus sit amet, sollicitudin quam. Proin condimentum purus dolor, ac egestas est consequat et. Vivamus molestie nisl diam, a scelerisque leo aliquet ut. In tincidunt elit mollis purus posuere tincidunt. Phasellus sit amet quam venenatis, pulvinar lorem nec, semper purus. Interdum et malesuada fames ac ante ipsum primis in faucibus.".as_bytes();

    let priv_key = secp256k1::generate_key(&mut rand).unwrap();

    let msg = [123u8; 32];

    let sig = secp256k1::sign(&priv_key, &msg[..]).unwrap();

    let pub_key = priv_key.public();
    secp256k1::verify(&pub_key, &msg[..], &sig).unwrap();
}
