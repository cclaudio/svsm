// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

/// C bindings
pub mod bindings;
/// TPM Commands
pub mod cmds;
/// TPM Endorsement key
pub mod ek;
/// MS Simulator functions
pub mod mssim;
/// MS TPM2 functions
pub mod mstpm;
/// Wrappers called in C
pub mod wrapper;

#[derive(Debug, Copy, Clone)]
pub enum VtpmError {
    Rc(u32),
}
