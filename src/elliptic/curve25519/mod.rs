//! module curve25519 provides an implementation of the X25519 function, which performs scalar
//! multiplication on the elliptic curve known as Curve25519. See [RFC 7748][1].
//!
//! [1]: http://tools.ietf.org/html/rfc7748

/// BASEPOINT is the canonical Curve25519 generator
pub const BASEPOINT: [u8; 32] = x25519_dalek::X25519_BASEPOINT_BYTES;

/// x25519 is an alias of [scalar_mult()](fn.scalar_mult.html).
pub use x25519_dalek::x25519;

/// scalar_mult calculates the product scalar * BASEPOINT.
pub use x25519_dalek::x25519 as scalar_mult;

/// scalar_base_mult calculates the product k * BASEPOINT, where k is a scalar
pub fn scalar_base_mult(k: [u8; 32]) -> [u8; 32] {
    x25519(k, BASEPOINT)
}
