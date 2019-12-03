use cryptographer::ed25519;
use cryptographer::rand::Rand;

#[test]
fn sign_verify() {
    let mut rand = Rand::new();

    let (priv_key, pub_key) = ed25519::generate_key(&mut rand).unwrap();

    let msg = "hello world".as_bytes();

    let sig = ed25519::sign(&priv_key, &msg);

    ed25519::verify(&pub_key, &msg, &sig).unwrap();
}
