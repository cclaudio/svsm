// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! RustCrypto implementation

extern crate alloc;

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, Key, KeyInit, Nonce,
};
use alloc::vec::Vec;
use sha2::{Sha512, Digest};

use crate::{
    crypto::aead::{
        Aes256Gcm as CryptoAes256Gcm, Aes256GcmTrait as CryptoAes256GcmTrait,
    },
    crypto::hashes::{
        Sha2 as CryptoSha2, Sha2Algorithms as CryptoSha2Algorithms,
    },
    protocols::errors::SvsmReqError,
};

#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq)]
enum AesGcmOperation {
    Encrypt = 0,
    Decrypt = 1,
}

fn aes_gcm_do(
    operation: AesGcmOperation,
    iv: &[u8],
    key: &[u8],
    aad: &[u8],
    inbuf: &[u8],
) -> Result<Vec<u8>, SvsmReqError> {
    let payload = Payload { msg: inbuf, aad };
    let aes_key = Key::<Aes256Gcm>::from_slice(key);
    let gcm = Aes256Gcm::new(aes_key);
    let nonce = Nonce::from_slice(iv);

    let result = if operation == AesGcmOperation::Encrypt {
        gcm.encrypt(nonce, payload)
    } else {
        gcm.decrypt(nonce, payload)
    };

    result.map_err(|_| SvsmReqError::invalid_format())
}

impl CryptoAes256GcmTrait for CryptoAes256Gcm {
    fn encrypt(
        iv: &[u8],
        key: &[u8],
        aad: &[u8],
        inbuf: &[u8],
    ) -> Result<Vec<u8>, SvsmReqError> {
        aes_gcm_do(AesGcmOperation::Encrypt, iv, key, aad, inbuf)
    }

    fn decrypt(
        iv: &[u8],
        key: &[u8],
        aad: &[u8],
        inbuf: &[u8],
    ) -> Result<Vec<u8>, SvsmReqError> {
        aes_gcm_do(AesGcmOperation::Decrypt, iv, key, aad, inbuf)
    }
}

impl CryptoSha2Algorithms for CryptoSha2 {
    fn sha512(data: &[u8]) -> Vec<u8> {
        Sha512::new()
            .chain_update(data)
            .finalize()
            .to_vec()
    }
}