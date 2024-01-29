// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Implement the Vtpm interface for the TPM 2.0
//! Reference Implementation (by Microsoft)

/// FFI bindings
mod bindings;
/// Functions required to build the Microsoft TPM libraries
mod wrapper;
