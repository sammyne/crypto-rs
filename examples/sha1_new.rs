cfg_if::cfg_if! {
    if #[cfg(feature = "sha1")] {

use std::io::Write;

use encoding::hex;

use cryptographer::{sha1, Hash};

fn main() {
    let mut h = sha1::new();

    h.write(b"His money is twice tainted:")
        .expect("failed to consume");

    h.write(b" 'taint yours and 'taint mine.")
        .expect("failed to consume");

    let got = {
        let v = h.sum();
        hex::encode_to_string(&v[..])
    };

    let expect = "597f6a540010f94c15d71806a99a2c8710e747bd";
    assert_eq!(&got, expect);
}

    }else {

fn main() {
    panic!("this example has been disabled due to missing feature 'sha1'");
}

    }

}
