# Cryptographer

[![CircleCI](https://circleci.com/gh/sammyne/cryptographer/tree/dev.svg?style=svg)](https://circleci.com/gh/sammyne/cryptographer/tree/dev)
[![docs badge](https://img.shields.io/badge/docs-0.4.0-blue)](https://sammyne.github.io/cryptographer/cryptographer/)

This repository tries to implement a Go-like crypto library in Rust.

## Algorithms

> The added time of every new algorithm should be recorded in the table below.

|  Algorithm | AddedAt(YY/MM/DD) |
| ---------: | :---------------- |
|        AES | 19/12/25          |
| Curve25519 | 19/12/30          |
|    ED25519 | 20/01/04          |
|       HMAC | 20/01/09          |
|        MD5 | 19/12/26          |
|        RC4 | 20/01/11          |
|  RIPEMD160 | 19/12/26          |
|       SHA3 | 20/03/06          |
|     subtle | 20/01/11          |

## Examples 
Just check the corresponding tests of the same names under the tests folder~

## FAQ
- Q: Why not separate each algorithm as small crates?
- A: There're some common trait depended by these cryptographic algorithms. If packing these 
    traits as a crate, it may happen that crates in this repository reference different versions
    of the common traits. Besides, if a crate of the same commit hash is specified with tag/rev, 
    it's treated as two crates by cargo, which has no fix right now. So I'd like to package all of 
    them into a large crate, and enable them through **features**.
