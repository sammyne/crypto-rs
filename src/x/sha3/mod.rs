//! module sha3 implements the SHA-3 fixed-output-length hash functions and the SHAKE
//! variable-output-length hash functions defined by FIPS-202.
//!
//! Both types of hash function use the "sponge" construction and the Keccak permutation. For a
//! detailed specification see [http://keccak.noekeon.org/][1].
//!
//! # Guidance
//! If you aren't sure what function you need, use SHAKE256 with at least 64 bytes of output. The
//! SHAKE instances are faster than the SHA3 instances; the latter have to allocate memory to
//! conform to the hash.Hash interface.
//!
//! If you need a secret-key MAC (message authentication code), prepend the secret key to the
//! input, hash with SHAKE256 and read at least 32 bytes of output.
//!
//! # Security strengths
//! The SHA3-x (x equals 224, 256, 384, or 512) functions have a security strength against preimage
//! attacks of x bits. Since they only produce "x" bits of output, their collision-resistance is
//! only "x/2" bits.
//!
//! The SHAKE-256 and -128 functions have a generic security strength of 256 and 128 bits against
//! all attacks, provided that at least 2x bits of their output is used. Requesting more than 64 or
//! 32 bytes of output, respectively, does not increase the collision-resistance of the SHAKE
//! functions.
//!
//! # The sponge construction
//! A sponge builds a pseudo-random function from a public pseudo-random permutation, by applying
//! the permutation to a state of "rate + capacity" bytes, but hiding "capacity" of the bytes.
//!
//! A sponge starts out with a zero state. To hash an input using a sponge, up to "rate" bytes of
//! the input are XORed into the sponge's state. The sponge is then "full" and the permutation is
//! applied to "empty" it. This process is repeated until all the input has been "absorbed". The
//! input is then padded. The digest is "squeezed" from the sponge in the same way, except that
//! output is copied out instead of input being XORed in.
//!
//! A sponge is parameterized by its generic security strength, which is equal to half its
//! capacity; capacity + rate is equal to the permutation's width. Since the KeccakF-1600
//! permutation is 1600 bits (200 bytes) wide, this means that the security strength of a sponge
//! instance is equal to (1600 - bitrate) / 2.
//!
//! # Recommendations
//! The SHAKE functions are recommended for most new uses. They can produce output of arbitrary
//! length. SHAKE256, with an output length of at least 64 bytes, provides 256-bit security against
//! all attacks. The Keccak team recommends it for most applications upgrading from SHA2-512. (NIST
//! chose a much stronger, but much slower, sponge instance for SHA3-512.)
//!
//! The SHA-3 functions are "drop-in" replacements for the SHA-2 functions. They produce output of
//! the same length, with the same security strengths against all attacks. This means, in
//! particular, that SHA3-256 only has 128-bit collision resistance, because its output length is
//! 32 bytes.
//!
//! [1]: http://keccak.noekeon.org/

use std::io::{Read, Write};

mod keccak256;
mod keccak512;
mod shake128;
mod shake256;
mod sum224;
mod sum256;
mod sum384;
mod sum512;

pub use crate::Hash;

pub use keccak256::*;
pub use keccak512::*;
pub use shake128::*;
pub use shake256::*;
pub use sum224::*;
pub use sum256::*;
pub use sum384::*;
pub use sum512::*;

/// ShakeHash specifies the trait for SHAKE-variant hash.
///
/// Clone returns a copy of the ShakeHash in its current state.
///
/// Read reads more output from the hash; reading affects the hash's state. (ShakeHash.Read is thus
/// very different from Hash.Sum)
/// It never returns an error.
///
/// Write absorbs more data into the hash's state. It panics if input is written to it after output
/// has been read from it.
///
/// @todo: implement the cshake128 and cshake256.
pub trait ShakeHash: Clone + Read + Write {
    /// reset resets the Hash to its initial state
    fn reset(&mut self);
}
