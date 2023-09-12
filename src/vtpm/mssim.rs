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

use core::ffi::c_void;

use crate::vtpm::bindings::{
    _plat__Signal_PowerOn, _plat__Signal_Reset,
    _plat__NVEnable, _plat__SetNvAvail, _plat__NVDisable,
};
use crate::vtpm::mstpm::{
    mstpm_manufacture, mstpm_teardown,
};
use crate::protocols::errors::SvsmReqError;
use crate::address::VirtAddr;

static mut VTPM_IS_POWERED_ON: bool = false;

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