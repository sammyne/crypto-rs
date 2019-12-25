use aes::block_cipher_trait::generic_array::GenericArray;
use aes::block_cipher_trait::BlockCipher;
use aes::{Aes128, Aes192, Aes256};

pub use super::cipher::Block;

pub const BLOCK_SIZE: usize = 16;

pub enum Cipher {
    AES128(Aes128),
    AES192(Aes192),
    AES256(Aes256),
}

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

pub fn new(key: &[u8]) -> Result<Cipher, Error> {
    match key.len() {
        16 => Ok(Cipher::AES128(Aes128::new(GenericArray::from_slice(&key)))),
        24 => Ok(Cipher::AES192(Aes192::new(GenericArray::from_slice(&key)))),
        32 => Ok(Cipher::AES256(Aes256::new(GenericArray::from_slice(&key)))),
        _ => Err(Error::KeySize(key.len())),
    }
}
