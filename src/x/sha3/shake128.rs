use std::io::{self, Read, Write};

use sha3::digest::{ExtendableOutput, Input};
use sha3::{Sha3XofReader, Shake128};

#[derive(Clone)]
enum State {
    Absorbing(Shake128),
    Reading(Sha3XofReader),
}

#[derive(Clone)]
pub struct SHAKE128 {
    state: State,
}

impl Read for SHAKE128 {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if let State::Absorbing(v) = &self.state {
            // clone is inefficient
            self.state = State::Reading(v.clone().xof_result());
        }

        match self.state {
            State::Reading(ref mut v) => v.read(buf),
            _ => panic!("unexpected state"),
        }
    }
}

impl Write for SHAKE128 {
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.state {
            State::Absorbing(ref mut v) => v.input(buf),
            State::Reading(_) => panic!("absorbing after reading"),
        }

        Ok(buf.len())
    }
}

impl super::ShakeHash for SHAKE128 {
    fn reset(&mut self) {
        self.state = State::Absorbing(Shake128::default());
    }
}

pub fn new_shake128() -> SHAKE128 {
    SHAKE128 {
        state: State::Absorbing(Shake128::default()),
    }
}

pub fn shake_sum128(hash: &mut [u8], b: &[u8]) -> io::Result<usize> {
    let mut h = new_shake128();

    let _ = h.write(b).expect("unfallible");
    h.read(hash)
}
