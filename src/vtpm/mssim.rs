// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

/// This crate implements the MS TPM Simulator interface defined in
/// https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/Simulator/include/TpmTcpProtocol.h
///
/// The same interface is also implemented in ms-tpm-20-ref/TPMCmd/Simulator/; we don't use it
/// because we are not compiling the TPM Simulator (-DSIMULATION=NO), as it brings in more
/// dependencies on libc and a higher memory footprint.

extern crate alloc;

use alloc::vec::Vec;
use core::ptr::{copy_nonoverlapping, write_bytes};
use core::ffi::c_void;

use crate::vtpm::bindings::{
    _plat__LocalitySet, _plat__RunCommand, _plat__Signal_PowerOn, _plat__Signal_Reset,
    _plat__NVEnable, _plat__SetNvAvail, _plat__NVDisable,
};
use crate::vtpm::mstpm::{
    mstpm_manufacture, mstpm_teardown,
};
use crate::protocols::errors::SvsmReqError;
use crate::protocols::vtpm::{TpmSendCommandRequest, TpmSendCommandResponse};
use crate::address::VirtAddr;
use crate::mm::{GuestPtr, PAGE_SIZE};

pub const TPM_BUFFER_MAX_SIZE: usize = PAGE_SIZE;

static mut VTPM_IS_POWERED_ON: bool = false;

/// Current MSSIM TPM commands we support. A complete list can be found in:
/// https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/Simulator/include/TpmTcpProtocol.h
const TPM_SEND_COMMAND: u32 = 8;

const TPM_SUPPORTED_CMDS: &[u32] = &[
    TPM_SEND_COMMAND,
];

pub fn mssim_platform_supported_commands() -> u64 {
    let mut bitmap: u64 = 0;

    for cmd in TPM_SUPPORTED_CMDS {
        bitmap |= 1u64 << *cmd;
    }

    bitmap
}

pub fn mssim_platform_request(command: u32, buffer: VirtAddr) -> Result<(), SvsmReqError> {
    match command {
        TPM_SEND_COMMAND => {
            mssim_send_tpm_command(buffer)?;
        },
        _ => return Err(SvsmReqError::unsupported_call()),
    }

    Ok(())
}

/// Send a TPM command for a given locality
pub fn mssim_send_tpm_command(buffer: VirtAddr) -> Result<(), SvsmReqError> {
    const REQ_INBUF_OFFSET: usize = core::mem::size_of::<TpmSendCommandRequest>();

    let guest_page = GuestPtr::<TpmSendCommandRequest>::new(buffer);
    let request = guest_page.read()?;

    // TODO: Before implementing locality, we need to agree what it means
    // to the platform
    if request.locality != 0 {
        return Err(SvsmReqError::invalid_parameter());
    }
    unsafe {
        if !VTPM_IS_POWERED_ON {
            return Err(SvsmReqError::invalid_request());
        }
    }

    let mut inbuf: Vec<u8> = Vec::with_capacity(TPM_BUFFER_MAX_SIZE);
    let inbuf_p: *mut u8 = inbuf.as_mut_ptr();

    let mut outbuf: Vec<u8> = Vec::with_capacity(TPM_BUFFER_MAX_SIZE);
    let mut outbuf_p: *mut u8 = outbuf.as_mut_ptr();
    let outbuf_pp: *mut *mut u8 = &mut outbuf_p;

    let mut outbuf_size = TPM_BUFFER_MAX_SIZE as u32;
    let outbuf_size_p = &mut outbuf_size;

    unsafe {
        // let b = core::slice::from_raw_parts(buffer.as_ptr::<u8>().add(REQ_INBUF_OFFSET), request.inbuf_size as usize);
        // let sz = request.inbuf_size;
        // log::info!("vTPM request buf({}) {:x?}", sz, b);

        copy_nonoverlapping(
            buffer.as_mut_ptr::<u8>().add(REQ_INBUF_OFFSET),
            inbuf_p,
            request.inbuf_size as usize,
        );

        _plat__LocalitySet(request.locality);

        _plat__RunCommand(
            request.inbuf_size,
            inbuf_p,
            outbuf_size_p,
            outbuf_pp,
        );
        outbuf.set_len(*outbuf_size_p as usize);

        // log::info!("vTPM response buf({}) {:x?}", *outbuf_size_p, outbuf);
    }

    // Request buffer not large enough to hold the response
    let max_out_buf_size = TPM_BUFFER_MAX_SIZE - core::mem::size_of::<TpmSendCommandResponse>();
    if *outbuf_size_p == 0 || *outbuf_size_p as usize > max_out_buf_size {
        return Err(SvsmReqError::invalid_parameter())
    }

    // Populate buffer with size and data
    unsafe {
        write_bytes(buffer.as_mut_ptr::<u8>(), 0, PAGE_SIZE);
        copy_nonoverlapping(
            outbuf_size_p as *const _ as *const u8,
            buffer.as_mut_ptr::<u8>(),
            4usize,
        );
        copy_nonoverlapping(
            outbuf.as_ptr() as *const u8,
            buffer.as_mut_ptr::<u8>().add(4),
            outbuf_size as usize,
        );
    }

    Ok(())
}

/// Initialize the vTPM
pub fn mssim_vtpm_init() -> Result<(), SvsmReqError> {
    // Manufacture the MS TPM following the same steps done in the Simulator:
    //
    // 1. Manufacture it for the first time
    // 2. Make sure it does not fail if it is re-manufactured
    // 3. Teardown to indicate it needs to be manufactured
    // 4. Manufacture it for the first time
    // 5. Power it on indicating it requires startup. By default, OVMF will start
    //    and selftest it.

    unsafe { _plat__NVEnable(VirtAddr::null().as_mut_ptr::<c_void>()); }

    let mut rc = mstpm_manufacture(1)?;
    if rc != 0 {
        unsafe { _plat__NVDisable(1); }
        return Err(SvsmReqError::incomplete());
    }

    rc = mstpm_manufacture(0)?;
    if rc != 1 {
        return Err(SvsmReqError::incomplete());
    }

    mstpm_teardown()?;
    rc = mstpm_manufacture(1)?;
    if rc != 0 {
        return Err(SvsmReqError::incomplete());
    }

    mssim_signal_poweron(false)?;
    mssim_signal_nvon()?;

    log::info!("vTPM manufactured");

    Ok(())
}

/// Power on the vTPM, which also triggers a reset
///
/// @only_reset:  If enabled, it will only reset the vTPM;
///               however, the vtPM has to be powered on previously.
///               Otherwise, it will fail.
pub fn mssim_signal_poweron(only_reset: bool) -> Result<(), SvsmReqError> {
    unsafe {
        if VTPM_IS_POWERED_ON && !only_reset {
            return Ok(());
        }
        if only_reset && !VTPM_IS_POWERED_ON {
            return Err(SvsmReqError::invalid_request());
        }
        if !only_reset {
            _plat__Signal_PowerOn();
        }

        // It calls TPM_init() within to indicate that a TPM2_Startup is required.
        _plat__Signal_Reset();

        VTPM_IS_POWERED_ON = true;
    }

    Ok(())
}


pub fn mssim_signal_nvon() -> Result<(), SvsmReqError> {
    unsafe {
        if !VTPM_IS_POWERED_ON {
            return Err(SvsmReqError::invalid_request());
        }
        _plat__SetNvAvail();
    }
    Ok(())
}