//! module aes implements AES encryption (formerly Rijndael), as defined in U.S. Federal Information
//! Processing Standards Publication 197

use vendored_aes::cipher::generic_array::GenericArray;
use vendored_aes::cipher::BlockCipher;
use vendored_aes::cipher::BlockDecrypt;
use vendored_aes::cipher::BlockEncrypt;
use vendored_aes::cipher::KeyInit;
use vendored_aes::{Aes128, Aes192, Aes256};

pub use super::cipher::Block;

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// Cipher enumerate AES variants based on different key sizes
pub enum Cipher {
    /// AES based on 128-bit keys
    AES128(Aes128),
    /// AES based on 192-bit keys
    AES192(Aes192),
    /// AES based on 256-bit keys
    AES256(Aes256),
}

/// Error enumerations related cryptographic operations in this module
#[derive(Debug)]
pub enum Error {
    KeySize(usize),
}

impl Block for Cipher {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn decrypt(&self, mut dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);

        let mut out = GenericArray::from_mut_slice(&mut dst);

        match self {
            Cipher::AES128(v) => v.decrypt_block(&mut out),
            Cipher::AES192(v) => v.decrypt_block(&mut out),
            Cipher::AES256(v) => v.decrypt_block(&mut out),
        };
    }

    fn encrypt(&self, mut dst: &mut [u8], src: &[u8]) {
        dst.copy_from_slice(src);

        let mut out = GenericArray::from_mut_slice(&mut dst);

        match self {
            Cipher::AES128(v) => v.encrypt_block(&mut out),
            Cipher::AES192(v) => v.encrypt_block(&mut out),
            Cipher::AES256(v) => v.encrypt_block(&mut out),
        };
    }
}

/// new_cipher creates and returns a new cipher.Block. The key argument should be the AES key,
/// either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256
pub fn new_cipher(key: &[u8]) -> Result<Cipher, Error> {
    match key.len() {
        16 => Ok(Cipher::AES128(Aes128::new(GenericArray::from_slice(&key)))),
        24 => Ok(Cipher::AES192(Aes192::new(GenericArray::from_slice(&key)))),
        32 => Ok(Cipher::AES256(Aes256::new(GenericArray::from_slice(&key)))),
        _ => Err(Error::KeySize(key.len())),
    }
}
