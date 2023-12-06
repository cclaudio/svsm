// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

extern crate alloc;

use core::mem::size_of;

use super::{
    bindings::{
        CreatePrimary_In, CreatePrimary_Out, FlushContext_In, TPM2_CreatePrimary,
        TPM2_FlushContext, TPMT_PUBLIC_Marshal, TPMT_PUBLIC,
    },
    VtpmError,
};
use alloc::{
    alloc::{alloc_zeroed, handle_alloc_error, Layout},
    boxed::Box,
    vec::Vec,
};
use bitflags::bitflags;

const TPM_RH_ENDORSEMENT: u32 = 0x4000_000b;

const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_AES: u16 = 0x0006;
const TPM_ALG_SHA256: u16 = 0x000b;
const TPM_ALG_NULL: u16 = 0x0010;
const TPM_ALG_CFB: u16 = 0x0043;

const TPM_ECC_NIST_P256: u16 = 0x0003;

const TPM_RC_SUCCESS: u32 = 0x0000_0000;

bitflags! {
    /// Reserved bits must be zero: [0, 3, 8-9, 12-15, 20-32]
    pub struct TpmaObject: u32 {
        const FixedTpm = 1 << 1;
        const StClear = 1 << 2;
        const FixedParent = 1 << 4;
        const SensitiveDataOrigin = 1 << 5;
        const UserWithAuth = 1 << 6;
        const AdminWithPolicy = 1 << 7;
        const NoDa = 1 << 10;
        const EncryptedDuplication = 1 << 11;
        const Restricted = 1 << 16;
        const Decrypt = 1 << 17;
        const SignEncrypt = 1 << 18;
        const X509Sign = 1 << 19;
    }
}

/// Create a primary rsa2048:aes128cfb key handle
pub fn vtpm_create_primary_rsa2048(
    authpolicy: &[u8],
    attributes: TpmaObject,
) -> Result<Box<CreatePrimary_Out>, VtpmError> {
    const TPM_ALG_RSA: u16 = 0x0001;
    // The CreatePrimary_In and CreatePrimary_Out structures are relatively big
    // to be allocated from stack, 608 and 760 bytes respectively.
    let mut create_out: Box<CreatePrimary_Out> = unsafe {
        let layout = Layout::new::<CreatePrimary_Out>();
        let addr = alloc_zeroed(layout);
        if addr.is_null() {
            handle_alloc_error(layout);
        }
        Box::from_raw(addr.cast::<CreatePrimary_Out>())
    };
    let mut create_in: Box<CreatePrimary_In> = unsafe {
        let layout = Layout::new::<CreatePrimary_In>();
        let addr = alloc_zeroed(layout);
        if addr.is_null() {
            handle_alloc_error(layout)
        }
        Box::from_raw(addr.cast::<CreatePrimary_In>())
    };

    create_in.primaryHandle = TPM_RH_ENDORSEMENT;
    create_in.inSensitive.sensitive.userAuth.t.size = 0;
    create_in.inSensitive.sensitive.data.t.size = 0;
    create_in.inPublic.size = size_of::<TPMT_PUBLIC>() as u16;
    create_in.inPublic.publicArea.type_ = TPM_ALG_RSA;
    create_in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    create_in.inPublic.publicArea.objectAttributes = attributes.bits();
    // Union read access is unsafe in Rust. authPolicy is a union.
    unsafe {
        let authpolicy_in = &mut create_in.inPublic.publicArea.authPolicy;
        authpolicy_in.t.size = authpolicy.len() as u16;
        authpolicy_in
            .t
            .buffer
            .get_mut(..authpolicy.len())
            .ok_or_else(|| VtpmError::Rc(111))?
            .copy_from_slice(&authpolicy);
    }
    let rsa_detail = unsafe { &mut create_in.inPublic.publicArea.parameters.rsaDetail };
    rsa_detail.symmetric.algorithm = TPM_ALG_AES;
    rsa_detail.symmetric.keyBits.aes = 128_u16;
    rsa_detail.symmetric.mode.aes = TPM_ALG_CFB;
    rsa_detail.scheme.scheme = TPM_ALG_NULL;
    rsa_detail.keyBits = 2048_u16;
    rsa_detail.exponent = 0;
    // The nonce (t.buffer) is already initialized with zeroes
    create_in.inPublic.publicArea.unique.rsa.t.size = 256_u16;
    create_in.outsideInfo.t.size = 0;
    create_in.creationPCR.count = 0;

    match unsafe { TPM2_CreatePrimary(create_in.as_mut(), create_out.as_mut()) } {
        TPM_RC_SUCCESS => Ok(create_out),
        tpm_rc => Err(VtpmError::Rc(tpm_rc)),
    }
}

/// Create a primary ECC key handle
/// ECC NISTP-256 bit key
pub fn vtpm_create_primary_ecc_p256(
    authpolicy: &[u8],
    attributes: TpmaObject,
) -> Result<Box<CreatePrimary_Out>, VtpmError> {
    // The CreatePrimary_In and CreatePrimary_Out structures are relatively big
    // to be allocated from stack, 608 and 760 bytes respectively.
    let mut create_out: Box<CreatePrimary_Out> = unsafe {
        let layout = Layout::new::<CreatePrimary_Out>();
        let addr = alloc_zeroed(layout);
        if addr.is_null() {
            handle_alloc_error(layout)
        }
        Box::from_raw(addr.cast::<CreatePrimary_Out>())
    };
    let mut create_in: Box<CreatePrimary_In> = unsafe {
        let layout = Layout::new::<CreatePrimary_In>();
        let addr = alloc_zeroed(layout);
        if addr.is_null() {
            handle_alloc_error(layout);
        }
        Box::from_raw(addr.cast::<CreatePrimary_In>())
    };

    create_in.primaryHandle = TPM_RH_ENDORSEMENT;
    create_in.inSensitive.sensitive.userAuth.t.size = 0;
    create_in.inSensitive.sensitive.data.t.size = 0;
    create_in.inPublic.size = size_of::<TPMT_PUBLIC>() as u16;
    create_in.inPublic.publicArea.type_ = TPM_ALG_ECC;
    create_in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
    create_in.inPublic.publicArea.objectAttributes = attributes.bits();
    // Union read access is unsafe in Rust. authPolicy is a union.
    unsafe {
        let authpolicy_in = &mut create_in.inPublic.publicArea.authPolicy;
        authpolicy_in.t.size = authpolicy.len() as u16;
        authpolicy_in
            .t
            .buffer
            .get_mut(..authpolicy.len())
            .ok_or_else(|| VtpmError::Rc(111))?
            .copy_from_slice(&authpolicy);
    }
    let ecc_detail = unsafe { &mut create_in.inPublic.publicArea.parameters.eccDetail };
    ecc_detail.curveID = TPM_ECC_NIST_P256;
    ecc_detail.symmetric.algorithm = TPM_ALG_AES;
    ecc_detail.symmetric.keyBits.aes = 128_u16;
    ecc_detail.symmetric.mode.aes = TPM_ALG_CFB;
    ecc_detail.scheme.scheme = TPM_ALG_NULL;
    ecc_detail.kdf.scheme = TPM_ALG_NULL;
    // The nonce (x and y buffers) is already initialized with zeroes
    create_in.inPublic.publicArea.unique.ecc.x.t.size = 32;
    create_in.inPublic.publicArea.unique.ecc.y.t.size = 32;
    create_in.outsideInfo.t.size = 0;
    create_in.creationPCR.count = 0;

    match unsafe { TPM2_CreatePrimary(create_in.as_mut(), create_out.as_mut()) } {
        TPM_RC_SUCCESS => Ok(create_out),
        tpm_rc => Err(VtpmError::Rc(tpm_rc)),
    }
}

/// Flush handle context from the TPM memory
pub fn vtpm_flush_context(handle: u32) -> Result<(), VtpmError> {
    let mut flush_in = FlushContext_In {
        flushHandle: handle,
    };

    match unsafe { TPM2_FlushContext(&mut flush_in) } {
        TPM_RC_SUCCESS => Ok(()),
        tpm_rc => Err(VtpmError::Rc(tpm_rc)),
    }
}

/// Marshal a TPMT_PUBLIC structure for transmission.
pub fn vtpm_tpmt_public_marshal(src: *mut TPMT_PUBLIC) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(size_of::<TPMT_PUBLIC>());
    let mut buf_p = buf.as_mut_ptr();
    let buf_pp = &mut buf_p;

    unsafe {
        let size = TPMT_PUBLIC_Marshal(src, buf_pp, core::ptr::null_mut::<i32>());
        buf.set_len(size.into());
    };

    buf
}
