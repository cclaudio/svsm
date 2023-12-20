// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::cell::OnceCell;

use crate::{locking::SpinLock, vtpm::cmds::vtpm_tpmt_public_marshal};

use super::{
    bindings::CreatePrimary_Out,
    cmds::{vtpm_create_primary_rsa2048, vtpm_flush_context, TpmaObject},
    VtpmError,
};

/// The EK public area is provided in the Attestation Runtime Protocol. Since the same
/// EK can be regenerated multiple times, we cache its public area at boot time to avoid
/// issues like TPM out-of-memory at runtime.
static TPM_EK: SpinLock<OnceCell<TpmEndorsementKey>> = SpinLock::new(OnceCell::new());

/// Public Area (TPMT_PUBLIC) of the Endorsement Key (EK).
#[derive(Debug)]
pub struct TpmEndorsementKey {
    /// Marshaled TPMT_PUBLIC
    public_area: Vec<u8>,
}

impl TpmEndorsementKey {
    /// Create an EK transient object and return its TPMT_PUBLIC public area.
    /// The transient object is flushed from TPM memory
    pub fn create() -> Result<TpmEndorsementKey, VtpmError> {
        // Policy A sha256: rsa2048:aes128cfb
        let authpolicy: [u8; 32] = [
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5,
            0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b,
            0x33, 0x14, 0x69, 0xaa,
        ];

        let attributes = TpmaObject::FixedTpm
            | TpmaObject::FixedParent
            | TpmaObject::SensitiveDataOrigin
            | TpmaObject::AdminWithPolicy
            | TpmaObject::Restricted
            | TpmaObject::Decrypt;

        // TODO: Replace the rsa2048 key by the ecc-p256 when the TPM_RC_NO_RESULT (0x154) is fixed.
        // This is likely to be related to the ECC issue we are having in the TPM Selftests, which we
        // workaround by setting "-DSELF_TEST=NO"
        //let mut create_out: Box<CreatePrimary_Out> =
        //    vtpm_create_primary_rsa2048(authpolicy.as_slice(), attributes)?;
        let mut create_out: Box<CreatePrimary_Out> = super::cmds::vtpm_create_primary_ecc_p256(authpolicy.as_slice(), attributes)?;

        // EK template is well known, see the TCG EK Credential Profile specification.
        // With the same Endorsement Primary Seed (EPS), the same EK can be regenerated
        // multiple times, as long as the same template (or attributes) is provided.
        if let Err(e) = vtpm_flush_context(create_out.objectHandle) {
            log::warn!(
                "Failed to flush the TPM EK transient handle {:#x}, e = {:#x?}",
                create_out.objectHandle,
                e
            );
        }

        let marshaled_ekpub = vtpm_tpmt_public_marshal(&mut create_out.outPublic.publicArea);

        Ok(TpmEndorsementKey {
            public_area: marshaled_ekpub,
        })
    }

    pub fn get_public_area(&self) -> Vec<u8> {
        self.public_area.clone()
    }
}

pub fn create_tpm_ek() {
    let _ = TPM_EK
        .lock()
        .get_or_init(|| match TpmEndorsementKey::create() {
            Ok(ek) => ek,
            Err(e) => panic!("Failed to create the TPM Endorsment Key {:#x?}", e),
        });
}

pub fn get_tpm_ek() -> Vec<u8> {
    TPM_EK.lock().get().unwrap().get_public_area()
}
