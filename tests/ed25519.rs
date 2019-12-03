use cryptographer::ed25519;

#[test]
fn sign_verify() {
    let mut rand = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin cursus enim at leo venenatis commodo. Morbi et luctus lectus. Vestibulum interdum nulla pulvinar, egestas purus sit amet, sollicitudin quam. Proin condimentum purus dolor, ac egestas est consequat et. Vivamus molestie nisl diam, a scelerisque leo aliquet ut. In tincidunt elit mollis purus posuere tincidunt. Phasellus sit amet quam venenatis, pulvinar lorem nec, semper purus. Interdum et malesuada fames ac ante ipsum primis in faucibus.".as_bytes();

    let (priv_key, pub_key) = ed25519::generate_key(&mut rand).unwrap();

    let msg = "hello world".as_bytes();

    let sig = ed25519::sign(&priv_key, &msg);

    ed25519::verify(&pub_key, &msg, &sig).unwrap();
}
