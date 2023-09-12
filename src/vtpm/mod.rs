// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

/// C bindings
pub mod bindings;
/// MS TPM2 functions
pub mod mstpm;
/// MS Simulator functions
pub mod mssim;
/// Wrappers called in C
pub mod wrapper;
