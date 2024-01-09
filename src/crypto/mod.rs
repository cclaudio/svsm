// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! SVSM kernel crypto API

pub mod aead {
    //! API for authentication encryption with associated data

    extern crate alloc;

    use alloc::vec::Vec;

    use crate::{protocols::errors::SvsmReqError, sev::secrets_page::VMPCK_SIZE};

    // Message Header Format (AMD SEV-SNP spec. table 98)

    /// Authenticated tag size (128 bits)
    pub const AUTHTAG_SIZE: usize = 16;
    /// Initialization vector size (96 bits)
    pub const IV_SIZE: usize = 12;
    /// Key size
    pub const KEY_SIZE: usize = VMPCK_SIZE;

    /// AES-256 GCM
    pub trait Aes256GcmTrait {
        /// Encrypt the provided buffer using AES-256 GCM
        ///
        /// # Arguments
        ///
        /// * `iv`: Initialization vector
        /// * `key`: 256-bit key
        /// * `aad`: Additional authenticated data
        /// * `inbuf`: Cleartext buffer to be encrypted
        ///
        /// # Returns
        ///
        /// * Success
        ///     * `Vec<u8>`: Encrypted `inbuf`
        /// * Error
        ///     * [SvsmReqError]
        fn encrypt(
            iv: &[u8],
            key: &[u8],
            aad: &[u8],
            inbuf: &[u8],
        ) -> Result<Vec<u8>, SvsmReqError>;

        /// Decrypt the provided buffer using AES-256 GCM
        ///
        /// # Returns
        ///
        /// * `iv`: Initialization vector
        /// * `key`: 256-bit key
        /// * `aad`: Additional authenticated data
        /// * `inbuf`: Cleartext buffer to be decrypted, followed by the authenticated tag
        ///
        /// # Returns
        ///
        /// * Success
        ///     * `Vec<u8>`: Decrypted `inbuf`
        /// * Error
        ///     * [SvsmReqError]
        fn decrypt(
            iv: &[u8],
            key: &[u8],
            aad: &[u8],
            inbuf: &[u8],
        ) -> Result<Vec<u8>, SvsmReqError>;
    }

    /// Aes256Gcm type
    #[derive(Copy, Clone, Debug)]
    pub struct Aes256Gcm;
}

pub mod hashes {
    extern crate alloc;

    use alloc::vec::Vec;

    pub trait Sha2Algorithms {
        /// Calculate a SHA512 hash over the data provided
        fn sha512(data: &[u8]) -> Vec<u8>;
    }

    #[derive(Copy, Clone, Debug)]
    pub struct Sha2;
}

// Crypto implementations supported. Only one of them must be compiled-in.

pub mod rustcrypto;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use crate::crypto::hashes::{Sha2, Sha2Algorithms};

    #[test]
    pub fn test_sha512() {
        let nonce = b"nonce-test";
        let manifest = b"manifest-test";
        // echo -n "nonce-testmanifest-test" | sha512sum
        let expected_digest =
            b"\xfb\xb2\x83\xab\x8c\xa9\xc0\x8e\
              \xc7\x37\x84\x15\x5d\xf2\x1c\x19\
              \x52\x13\x04\x67\x09\x27\x18\x66\
              \xbe\xdb\x90\x1a\x82\xae\x3e\x13\
              \x34\x61\xaa\x06\x6c\xd1\x81\x4c\
              \xb5\xa2\xa0\x26\xa8\xc2\xce\x29\
              \x6f\xae\x11\xa8\x19\x0b\x2d\xf1\
              \xc6\x58\xbe\xa6\xc6\x63\x59\x29";

        let mut data = Vec::<u8>::with_capacity(nonce.len() + manifest.len());
        data.extend_from_slice(nonce);
        data.extend_from_slice(manifest);

        let digest = Sha2::sha512(data.as_slice());
        assert_eq!(digest.as_slice(), expected_digest);
    }
}