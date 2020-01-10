use super::internal::subtle;

pub struct Cipher {
    states: [u8; 256],
    i: u8,
    j: u8,
}

/// Error enumerations related cryptographic operations in this module
#[derive(Debug)]
pub enum Error {
    KeySize(usize),
}

impl Cipher {
    pub fn reset(&mut self) {
        for v in &mut self.states[..] {
            *v = 0;
        }

        self.i = 0;
        self.j = 0;
    }

    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) {
        if src.len() == 0 {
            return;
        }

        if subtle::inexact_overlap(dst, src) {
            panic!("crypto/rc4: invalid buffer overlap")
        }

        let mut i = self.i;
        let mut j = self.j;

        let _ = dst[src.len() - 1];
        let (dst, ..) = dst.split_at_mut(src.len()); // eliminate bounds check from loop
        for (k, v) in src.iter().enumerate() {
            i = i.wrapping_add(1);
            let x = self.states[i as usize];
            j = j.wrapping_add(x);
            let y = self.states[j as usize];

            self.states[i as usize] = y;
            self.states[j as usize] = x;
            dst[k] = v ^ self.states[x.wrapping_add(y) as usize];
        }

        self.i = i;
        self.j = j;
    }
}

pub fn new(key: &[u8]) -> Result<Cipher, Error> {
    let key_len = key.len();
    if key_len < 1 || key_len > 256 {
        return Err(Error::KeySize(key_len));
    }

    let mut states = [0u8; 256];
    for i in 0..states.len() {
        states[i] = i as u8;
    }

    let mut j = 0u8;
    for i in 0..states.len() {
        j = j.wrapping_add(states[i].wrapping_add(key[i % key_len]));

        let tmp = states[i];
        states[i] = states[j as usize];
        states[j as usize] = tmp;
    }
    Ok(Cipher { states, i: 0, j: 0 })
}
