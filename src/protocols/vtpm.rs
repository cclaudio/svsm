// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2023 IBM Corp
//
// Author: Claudio Carvalho <cclaudio@linux.ibm.com>

/// vTPM Protocol defined in the Chapter 8 of the SVSM spec v0.62.

use crate::address::{PhysAddr, Address};
use crate::mm::{valid_phys_address, PerCPUPageMappingGuard, GuestPtr, PAGE_SIZE};
use crate::protocols::RequestParams;
use crate::protocols::errors::SvsmReqError;
use crate::vtpm::mssim::{mssim_platform_request, mssim_platform_supported_commands};

/// Table 14: vTPM Protocol Services
const SVSM_VTPM_QUERY: u32 = 0;
const SVSM_VTPM_COMMAND: u32 = 1;

/// Table 15: vTPM Common Request/Response Structure
///
/// Each MSSIM TPM command can build upon this common request/response
/// structure to create a structure specific to the command.
///
/// @command:  gPA of the MSIM TPM Command structure.
///            The first field of this structure must be
///            the command number.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct VtpmCmdRequest {
    command: u32,
}

/// Table 16: TPM_SEND_COMMAND request structure
///
/// @command:  The command (must be TPM_SEND_COMMAND)
/// @locality:  The locality
/// @inbuf_size:  The size of the input buffer following
/// @inbuf:  A buffer of size inbuf_size
///
/// Note that @inbuf_size must be large enough to hold the response so
/// it represents the maximum buffer size, not the size of the specific
/// TPM command.
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TpmSendCommandRequest {
    pub command: u32,
    pub locality: u8,
    pub inbuf_size: u32,
    //pub inbuf: u64,
}

/// Table 17: TPM_SEND_COMMAND response structure
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TpmSendCommandResponse {
    pub outbuf_size: u32,
    //pub outbuf: u64,
}

fn vtpm_command_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    if params.rcx == 0 {
        log::info!("SVSM: vtpm command probe");
        return Ok(());
    }

    let paddr = PhysAddr::from(params.rcx);

    if !valid_phys_address(paddr) {
        log::error!("vTPM buffer not valid physical address {} {}", paddr, params.rcx);
        return Err(SvsmReqError::invalid_parameter());
    }

    // The buffer gpa size is one page, but it not required to be page aligned.
    let start = paddr.page_align();
    let offset = paddr.page_offset();
    let end = (paddr + PAGE_SIZE).page_align_up();

    let guard = PerCPUPageMappingGuard::create(start, end, 0)?;
    let vaddr = guard.virt_addr() + offset;

    let guest_page = GuestPtr::<VtpmCmdRequest>::new(vaddr);
    let request = guest_page.read()?;

    mssim_platform_request(request.command, vaddr)?;

    Ok(())
}

fn vtpm_query_request(params: &mut RequestParams) -> Result<(), SvsmReqError> {
    // Bitmap of the supported vTPM commands
    params.rcx = mssim_platform_supported_commands();
    // Supported vTPM features. Must-be-zero
    params.rdx = 0;

    Ok(())
}

pub fn vtpm_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    match request {
        SVSM_VTPM_QUERY => vtpm_query_request(params),
        SVSM_VTPM_COMMAND => vtpm_command_request(params),
        _ => Err(SvsmReqError::unsupported_call()),
    }
}