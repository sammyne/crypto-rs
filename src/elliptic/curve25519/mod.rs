pub const BASEPOINT: [u8; 32] = x25519_dalek::X25519_BASEPOINT_BYTES;

pub use x25519_dalek::x25519;

pub fn scalar_base_mult(k: [u8; 32]) -> [u8; 32] {
    x25519(k, BASEPOINT)
}
