/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 *          Dov Murik <dovmurik@linux.ibm.com>
 */

extern crate alloc;

use alloc::vec::Vec;
use sha2::{Sha512, Digest};
use core::mem::size_of;
use core::slice::{from_raw_parts_mut, from_raw_parts};

use crate::address::{PhysAddr, Address, VirtAddr};

use crate::fw_meta::Uuid;
use crate::greq::services::{get_regular_report, get_extended_report};
use crate::mm::{PerCPUPageMappingGuard, GuestPtr};

use super::RequestParams;
use super::errors::{SvsmReqError, SvsmResultCode};
use super::services_manifest::{build_service_manifest_one, build_service_manifest_all};

/// SVSM spec, Table 10: Attestation Protocol Services
const SVSM_ATTEST_SERVICES: u32 = 0;
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;

const SVSM_FAIL_SNP_ATTESTATION: u64 = 0x8000_1000;

#[derive(Debug)]
struct AttestationResult {
    code: SvsmResultCode,
    services_manifest_size: usize,
    certs_size: usize,
    report_size: usize,
}

impl AttestationResult {
    pub fn from_code(code: SvsmResultCode) -> Self {
        Self { code, services_manifest_size: 0, certs_size: 0, report_size: 0 }
    }
    
    pub fn update_params(&self, params: &mut RequestParams) {
        params.rcx = self.services_manifest_size as u64;
        params.rdx = self.certs_size as u64;
        params.r8 = self.report_size as u64;
    }
}

fn check_fits_into_one_page(gpa: PhysAddr, size: usize) -> Result<(), AttestationResult> {
    if gpa.page_align() == (gpa + size).page_align() {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))
    }
}

fn check_aligned(gpa: PhysAddr, align: usize) -> Result<(), AttestationResult> {
    if gpa.is_aligned(align) {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))
    }
}

fn check_page_aligned(gpa: PhysAddr) -> Result<(), AttestationResult> {
    if gpa.is_page_aligned() {
        Ok(())
    } else {
        Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))
    }
}

fn map_gpa_into_one_page(gpa: PhysAddr, size: usize, align: usize) -> Result<(PerCPUPageMappingGuard, VirtAddr), AttestationResult> {
    check_aligned(gpa, align)?;

    // The nonce must not cross a 4KB boundary
    check_fits_into_one_page(gpa, size)?;

    // The nonce is not required to be page aligned
    let mapping = PerCPUPageMappingGuard::create_4k(gpa.page_align())
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;
    let gva: VirtAddr = mapping.virt_addr() + gpa.page_offset();
    Ok((mapping, gva))
}

fn map_page_aligned_buffer<'a>(gpa: PhysAddr, size: usize) -> Result<(PerCPUPageMappingGuard, &'a [u8]), AttestationResult> {
    check_page_aligned(gpa)?;
    let mapping = PerCPUPageMappingGuard::create(
        gpa,
        (gpa + size).page_align_up(),
        0,
    )
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;
    let u8_slice = unsafe { from_raw_parts_mut(mapping.virt_addr().as_mut_ptr::<u8>(), size) };
    Ok((mapping, u8_slice))
}

/// SVSM Spec Chapter 7 (Attestation): Table 11: Attest Services operation
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct AttestServicesRequest {
    report_gpa: u64,
    report_size: u32,
    _reserved1: [u8; 4],
    nonce_gpa: u64,
    nonce_size: u16,
    _reserved2: [u8; 6],
    services_manifest_gpa: u64,
    services_manifest_size: u32,
    _reserved3: [u8; 4],
    certs_gpa: u64,
    certs_size: u32,
    _reserved4: [u8; 4],
}

impl AttestServicesRequest {
    fn build_report_data(&self, manifest: &Vec<u8>) -> Result<Vec<u8>, AttestationResult> {
        let nonce_gpa = PhysAddr::from(self.nonce_gpa);

        // The nonce must not cross a 4KB boundary and it's not
        // required to be page aligned
        let (nonce_map, nonce_gva) = map_gpa_into_one_page(nonce_gpa,usize::from(self.nonce_size), 8)?;
        let nonce_slice: &[u8] = unsafe { from_raw_parts(nonce_gva.as_ptr::<u8>(), self.nonce_size as usize) };

        // use rustcrypto to calculate a sha512 hash
        let report_data: Vec<u8> = Sha512::new()
            .chain_update(nonce_slice)
            .chain_update(manifest.as_slice())
            .finalize().to_vec();
        
        Ok(report_data)
    }

    pub fn attest_service_manifest(
        &mut self,
        manifest: &Vec<u8>,
    ) -> Result<AttestationResult, AttestationResult> {
        let report_gpa = PhysAddr::from(self.report_gpa);
        let manifest_gpa = PhysAddr::from(self.services_manifest_gpa);
        let certs_gpa = PhysAddr::from(self.certs_gpa);
        
        //check_page_aligned(report_gpa)?;
        //check_page_aligned(manifest_gpa)?;

        let report_data = self.build_report_data(manifest)?;

        let (report_map, report_outbuf) = map_page_aligned_buffer(report_gpa, self.report_size as usize)?;

        // let report_map = PerCPUPageMappingGuard::create(report_gpa, (report_gpa + self.report_size).page_align_up(), 0)?;
        // let report_outbuf = unsafe { from_raw_parts_mut(report_map.virt_addr().as_mut_ptr::<u8>(), self.report_size as usize) };

        let (manifest_map, manifest_outbuf) = map_page_aligned_buffer(manifest_gpa, self.services_manifest_size as usize)?;

        // let manifest_map = PerCPUPageMappingGuard::create(manifest_gpa, (manifest_gpa + self.services_manifest_size).page_align_up(), 0)?;
        // let manifest_outbuf = unsafe { from_raw_parts_mut(manifest_map.virt_addr().as_mut_ptr::<u8>(), self.services_manifest_size as usize) };

        let (certs_map, certs_outbuf) = if self.certs_size > 0 {
            if certs_gpa.is_null() {
                return Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER));
            }
            //check_page_aligned(certs_gpa)?;
            let (map, outbuf) = map_page_aligned_buffer(certs_gpa, self.certs_size as usize)?;
            // let map = PerCPUPageMappingGuard::create(certs_gpa, (certs_gpa + self.certs_size as usize).page_align_up(), 0)?;
            // let outbuf = unsafe { from_raw_parts_mut(map.virt_addr().as_mut_ptr::<u8>(), self.certs_size as usize) };
            (Some(map), Some(outbuf))
        } else {
            (None, None)
        };

        if manifest.len() > manifest_outbuf.len() {
            return Err(
                AttestationResult {
                    code: SvsmResultCode::INVALID_PARAMETER,
                    services_manifest_size: manifest.len(),
                    certs_size: 0,
                    report_size: 0,
                }
            );
        }

        let mut certs_size: usize = 0;

        let (report, certs) = if self.certs_size > 0 {
            let (r, c) =  get_extended_report(report_data)
                .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))?;
            certs_size = c.len();
            if c.len() > self.certs_size as usize {
                return Err(
                    AttestationResult {
                        code: SvsmResultCode::INVALID_PARAMETER,
                        services_manifest_size: manifest.len(),
                        certs_size,
                        report_size: 0,
                    }
                );
            }
            (r, Some(c))
        } else {
            let r = get_regular_report(report_data)
                .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))?;
            (r, None)
        };

        if report.len() > self.report_size as usize {
            return Err(
                AttestationResult {
                    code: SvsmResultCode::INVALID_PARAMETER,
                    services_manifest_size: manifest.len(),
                    certs_size,
                    report_size: report.len(),
                }
            );
        }

        manifest_outbuf[..manifest.len()].copy_from_slice(&manifest);
        report_outbuf[..report.len()].copy_from_slice(&report);
        if let (Some(mut outbuf), Some(c)) = (certs_outbuf, certs) {
            outbuf[..c.len()].copy_from_slice(&c);
        }

        Ok( AttestationResult {
            code: SvsmResultCode::SUCCESS,
            services_manifest_size: manifest.len(),
            certs_size,
            report_size: report.len(),
        })
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 13: Attest Single Service operation
#[derive(Clone, Copy, Debug)]
#[repr(C, packed)]
struct AttestSingleServiceRequest {
    base: AttestServicesRequest,
    service_guid: [u8; 16],
    manifest_version: u32,
    _reserved5: [u8; 4],
}

fn handle_attest_services_request(params: &mut RequestParams) ->Result<AttestationResult, AttestationResult> {
    let request_gpa = PhysAddr::from(params.rcx);
    let request_size = size_of::<AttestServicesRequest>();

    // TODO: ensure the gpas are not in the SVSM address space

    // The AttestServicesRequest structure must not cross 4KB boundary and
    // it's not required to be page aligned
    let (_request_map, request_gva) = map_gpa_into_one_page(request_gpa, request_size, 8)?;

    let guest_ptr = GuestPtr::<AttestServicesRequest>::new(request_gva);
    let mut request = guest_ptr
        .read()
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_ADDRESS))?;

    let manifest = build_service_manifest_all();
    
    request.attest_service_manifest(&manifest)






    // let request_gpa: PhysAddr = PhysAddr::new((*vmsa).rcx());
    // let r: AttestationResult = match handle_attest_services_request_inner(request_gpa) {
    //     Ok(r) => r,
    //     Err(r) => r,
    // };
    // (*vmsa).set_rax(r.code);
    // (*vmsa).set_rcx(r.services_manifest_size);
    // (*vmsa).set_rdx(r.certs_size);
    // (*vmsa).set_r8(r.report_size);
}


fn handle_attest_single_service_request(params: &mut RequestParams) -> Result<AttestationResult, AttestationResult> {
    let request_gpa = PhysAddr::from(params.rcx);
    let request_size = size_of::<AttestSingleServiceRequest>();

    check_fits_into_one_page(request_gpa, request_size)?;

    let mapping = PerCPUPageMappingGuard::create(
        request_gpa.page_align(),
        (request_gpa + request_size).page_align_up(),
        0,
    )
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;

    // The AttestSingleServiceRequest structure is not required to be page aligned
    let request_gva = mapping.virt_addr() + request_gpa.page_offset();
    let guest_ptr = GuestPtr::<AttestSingleServiceRequest>::new(request_gva);
    let mut request = guest_ptr
        .read()
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_ADDRESS))?;

    let service_guid = Uuid::from(&request.service_guid);
    let manifest = build_service_manifest_one(&service_guid)
        .ok_or_else(|| AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))?;

    request.base.attest_service_manifest(manifest)



    // /// set params accordingly
    // /// certificate data buffer too small
    // ///     RCX = manifest size
    // ///     RDX = certificate size required
    // ///     INVALID_PARAMETER
    // /// 
    // /// report buffer too small
    // ///     RCX = manifest size
    // ///     RDX = certificate size, if supplied
    // ///     R8 = attestation report size required
    // ///     INVALID_PARAMETER

    // // Upon successful completion of the attestation request
    // request.base.set_report(report);
    // request.base.set_manifest(manifest);
    // params.rcx = manifest.len();
    // // if certs gpa is provided
    // request.base.set_certs(certs);
    // params.rdx = certs.len();

    // // if attestation request fails
    // params.rax = 0x8000_1000;

    // // let r: AttestationResult = match handle_attest_single_services_request_inner(request_gpa) {
    // //     Ok(r) => r,
    // //     Err(r) => r,
    // // };
    // // (*vmsa).set_rax(r.code);
    // // (*vmsa).set_rcx(r.services_manifest_size);
    // // (*vmsa).set_rdx(r.certs_size);
    // // (*vmsa).set_r8(r.report_size);
}

pub fn attestation_protocol_request(request: u32, params: &mut RequestParams) -> Result<(), SvsmReqError> {
    let result = match request {
        SVSM_ATTEST_SERVICES => handle_attest_services_request(params),
        SVSM_ATTEST_SINGLE_SERVICE => handle_attest_single_service_request(params),
        _ => return Err(SvsmReqError::unsupported_call()),
    };

    match result {
        Ok(r) => {
            r.update_params(params);
            Ok(())
        }
        Err(r) => {
            r.update_params(params);
            Err(SvsmReqError::RequestError(r.code))
        }
    }
}
