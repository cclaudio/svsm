// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! API to send `SNP_GUEST_REQUEST` commands to the PSP

extern crate alloc;

use alloc::vec::Vec;

use crate::{
    greq::{
        driver::{send_extended_guest_request, send_regular_guest_request},
        msg::SnpGuestRequestMsgType,
        pld_report::{SnpReportRequest, SnpReportResponse},
    },
    protocols::errors::SvsmReqError,
};

/// Request a regular VMPL0 attestation report to the PSP.
///
/// Use the `SNP_GUEST_REQUEST` driver to send the provided `MSG_REPORT_REQ` command to
/// the PSP. The VPML field of the command must be set to zero.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `report_data`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///             sent to the PSP. It must be large enough to hold the
///             [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
///
/// # Returns
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match the
///        [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
pub fn get_regular_report(report_data: Vec<u8>) -> Result<Vec<u8>, SvsmReqError> {
    let mut request = SnpReportRequest::new();
    request.set_report_data(report_data)?;

    let response_vec = send_regular_guest_request(
        SnpGuestRequestMsgType::ReportRequest,
        request.as_slice(),
    )?;

    let response: &SnpReportResponse = SnpReportResponse::try_from_as_ref(response_vec.as_slice())?;
    let report_vec: Vec<u8> = response.get_report_vec()?;

    Ok(report_vec)
}

/// Request an extended VMPL0 attestation report to the PSP.
///
/// We say that it is extended because it requests a VMPL0 attestation report
/// to the PSP (as in [`get_regular_report()`]) and also requests to the hypervisor
/// the certificates required to verify the attestation report.
///
/// The VMPCK0 is disabled for subsequent calls if this function fails in a way that
/// the VM state can be compromised.
///
/// # Arguments
///
/// * `report_data`: Buffer with the [`MSG_REPORT_REQ`](SnpReportRequest) command that will be
///             sent to the PSP. It must be large enough to hold the
///             [`MSG_REPORT_RESP`](SnpReportResponse) received from the PSP.
///
/// # Return codes
///
/// * Success
///     * `usize`: Number of bytes written to `buffer`. It should match
///                the [`MSG_REPORT_RESP`](SnpReportResponse) size.
/// * Error
///     * [`SvsmReqError`]
///     * `SvsmReqError::FatalError(SvsmError::Ghcb(GhcbError::VmgexitError(certs_buffer_size, psp_rc)))`:
///         * `certs` is not large enough to hold the certificates.
///             * `certs_buffer_size`: number of bytes required.
///             * `psp_rc`: PSP return code
pub fn get_extended_report(report_data: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), SvsmReqError> {
    let mut request = SnpReportRequest::new();
    request.set_report_data(report_data)?;

    let (response_vec, certs) = send_extended_guest_request(
        SnpGuestRequestMsgType::ReportRequest,
        request.as_slice(),
    )?;

    let response: &SnpReportResponse = SnpReportResponse::try_from_as_ref(response_vec.as_slice())?;
    let report_vec: Vec<u8> = response.get_report_vec()?;

    Ok((report_vec, certs))
}
