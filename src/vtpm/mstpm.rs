// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

// This crate make calls to the Microsoft libtpm.a built from ms-tpm-20-ref/TPMCmd/tpm.
// The libtpm implements the commands defined in the "TCG TPM 2.0 - Part 3" specification.

use crate::protocols::errors::SvsmReqError;
use crate::vtpm::bindings::{TPM_Manufacture, TPM_TearDown};

/// Prepare the TPM for re-manufacture.
pub fn mstpm_teardown() -> Result<(), SvsmReqError> {
    unsafe {
        match TPM_TearDown() {
            0 => Ok(()),
            rc => {
                log::error!("TPM_Teardown failed rc={}", rc);
                Err(SvsmReqError::incomplete())
            }
        }
    }
}

/// Initialize the TPM values in preparation for the TPM's first use.
/// This function will fail if previously called. The TPM can be re-manufactured
/// by calling mstpm_teardown() first and then calling this function again.
pub fn mstpm_manufacture(first_time: i32) -> Result<i32, SvsmReqError> {
    unsafe {
        // Return Type: int
        //      -1          failure
        //      0           success
        //      1           manufacturing process previously performed
        match TPM_Manufacture(first_time) {
            // TPM manufactured successfully
            0 => Ok(0),
            // TPM already manufactured
            1 => Ok(1),
            // TPM failed to manufacture
            rc => {
                log::error!("TPM_Manufacture failed rc={}", rc);
                Err(SvsmReqError::incomplete())
            }
        }
    }
}
