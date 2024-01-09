// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM Corporation
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
//          Dov Murik <dovmurik@linux.ibm.com>

extern crate alloc;

use alloc::vec::Vec;
use core::{
    mem::size_of,
    slice::{from_raw_parts_mut, from_raw_parts},
};

use crate::{
    address::{Address, PhysAddr, VirtAddr},
    crypto::hashes::{Sha2, Sha2Algorithms},
    greq::services::{get_extended_report, get_regular_report},
    mm::{GuestPtr, PerCPUPageMappingGuard, valid_phys_address},
    protocols::{
        errors::{SvsmReqError, SvsmResultCode},
        RequestParams,
        services_manifest::{build_service_manifest_all, build_service_manifest_one},
    },
    utils::uuid::Uuid,
};

/// SVSM spec, Table 10: Attestation Protocol Services
const SVSM_ATTEST_SERVICES: u32 = 0;
const SVSM_ATTEST_SINGLE_SERVICE: u32 = 1;

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

/// Map a guest physical address into one page.
fn map_gpa_into_4k_page(gpa: PhysAddr, size: usize, align: usize) -> Result<PerCPUPageMappingGuard, AttestationResult> {
    if gpa.crosses_page(size) || !gpa.is_aligned(align) || !valid_phys_address(gpa) {
        return Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER));
    }
    let mapping = PerCPUPageMappingGuard::create_4k(gpa.page_align())
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;

    Ok(mapping)
}

/// Map a guest physical address (GPA). The GPA must be page aligned.
fn map_page_aligned_buffer(gpa: PhysAddr, size: usize) -> Result<PerCPUPageMappingGuard, AttestationResult> {
    if !gpa.is_page_aligned() || !valid_phys_address(gpa) {
        return Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER));
    }
    let mapping = PerCPUPageMappingGuard::create(
        gpa,
        (gpa + size).page_align_up(),
        0,
    )
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;
    Ok(mapping)
}

/// SVSM Spec Chapter 7 (Attestation): Table 11: Attest Services operation
#[derive(Clone, Copy, Debug)]
#[repr(C)]
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
    fn build_report_data(&self, manifest: &[u8]) -> Result<Vec<u8>, AttestationResult> {
        let nonce_gpa = PhysAddr::from(self.nonce_gpa);
        let nonce_size = usize::from(self.nonce_size);

        // The nonce must not cross a 4KB boundary and it's not
        // required to be page aligned
        let nonce_map = map_gpa_into_4k_page(nonce_gpa, nonce_size, 8)?;
        let nonce_gva: VirtAddr = nonce_map.virt_addr() + nonce_gpa.page_offset();
        let nonce: &[u8] = unsafe { from_raw_parts(nonce_gva.as_ptr::<u8>(), nonce_size) };

        let mut data = Vec::<u8>::with_capacity(nonce.len() + manifest.len());
        data.extend_from_slice(nonce);
        data.extend_from_slice(manifest);

        let report_data: Vec<u8> = Sha2::sha512(data.as_slice());
        Ok(report_data)
    }

    pub fn attest_service_manifest(
        &mut self,
        manifest: &Vec<u8>,
    ) -> Result<AttestationResult, AttestationResult> {
        let report_gpa = PhysAddr::from(self.report_gpa);
        let manifest_gpa = PhysAddr::from(self.services_manifest_gpa);
        let certs_gpa = PhysAddr::from(self.certs_gpa);

        let report_size = self.report_size as usize;
        let manifest_size = self.services_manifest_size as usize;
        let certs_size = self.certs_size as usize;

        // The SVSM spec says that the provided output buffers (report,
        // manifest and certs) must be updated ONLY upon successful completion
        // of the SNP attestation request.

        let report_map = map_page_aligned_buffer(report_gpa, report_size)?;
        let report_outbuf = unsafe { from_raw_parts_mut(report_map.virt_addr().as_mut_ptr::<u8>(), report_size) };

        let manifest_map = map_page_aligned_buffer(manifest_gpa, manifest_size)?;
        let manifest_outbuf = unsafe { from_raw_parts_mut(manifest_map.virt_addr().as_mut_ptr::<u8>(), manifest_size) };

        let certs_map = if certs_size > 0 {
            if certs_gpa.is_null() {
                return Err(AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER));
            }
            let map = map_page_aligned_buffer(certs_gpa, certs_size)?;
            Some(map)
        } else {
            None
        };

        // Check if the manifest fits into the output buffer
        let manifest_outslice = manifest_outbuf
            .get_mut(..manifest.len())
            .ok_or_else(|| AttestationResult {
                code: SvsmResultCode::INVALID_PARAMETER,
                services_manifest_size: manifest.len(),
                certs_size: 0,
                report_size: 0,
            }
        )?;

        // Build the report data and request the attestation report
        let report_data = self.build_report_data(manifest.as_slice())?;
        let mut certs_len: usize = 0;
        let (report, certs) = if self.certs_size > 0 {
            let (r, c) =  get_extended_report(report_data.as_slice())
                .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;
            certs_len = c.len();
            (r, Some(c))
        } else {
            let r = get_regular_report(report_data.as_slice())
                .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_REQUEST))?;
            (r, None)
        };

        // Check if the returned report fits into the output buffer
        let report_outslice = report_outbuf
            .get_mut(..report.len())
            .ok_or_else(|| AttestationResult {
                    code: SvsmResultCode::INVALID_PARAMETER,
                    services_manifest_size: manifest.len(),
                    certs_size: certs_len,
                    report_size: report.len(),
                }
            )?;

        // Lastly, check if the returned certificates fit into the
        // output buffer. If so, we can start updating all the output buffers.
        if let (Some(map), Some(c)) = (certs_map, certs) {
            let certs_outbuf = unsafe { from_raw_parts_mut(map.virt_addr().as_mut_ptr::<u8>(), certs_size) };
            let certs_outslice = certs_outbuf
                .get_mut(..certs_len)
                .ok_or_else(|| AttestationResult {
                        code: SvsmResultCode::INVALID_PARAMETER,
                        services_manifest_size: manifest.len(),
                        certs_size: certs_len,
                        report_size: 0,
                    }
                )?;
            certs_outslice.copy_from_slice(c.as_slice());
        }

        manifest_outslice.copy_from_slice(manifest.as_slice());
        report_outslice.copy_from_slice(report.as_slice());

        Ok( AttestationResult {
            code: SvsmResultCode::SUCCESS,
            services_manifest_size: manifest.len(),
            certs_size: certs_len,
            report_size: report.len(),
        })
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 13: Attest Single Service operation
#[derive(Clone, Copy, Debug)]
#[repr(C)]
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
    let request_map = map_gpa_into_4k_page(request_gpa, request_size, 8)?;
    let request_gva = request_map.virt_addr() + request_gpa.page_offset();

    let guest_ptr = GuestPtr::<AttestServicesRequest>::new(request_gva);
    let mut request = guest_ptr
        .read()
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_ADDRESS))?;

    let manifest = build_service_manifest_all();

    request.attest_service_manifest(&manifest)
}

fn handle_attest_single_service_request(params: &mut RequestParams) -> Result<AttestationResult, AttestationResult> {
    let request_gpa = PhysAddr::from(params.rcx);
    let request_size = size_of::<AttestSingleServiceRequest>();

    // The AttestSingleServiceRequest structure must not cross 4KB boundary and
    // it's not required to be page aligned
    let request_map = map_gpa_into_4k_page(request_gpa, request_size, 8)?;
    let request_gva = request_map.virt_addr() + request_gpa.page_offset();

    let guest_ptr = GuestPtr::<AttestSingleServiceRequest>::new(request_gva);
    let mut request = guest_ptr
        .read()
        .map_err(|_| AttestationResult::from_code(SvsmResultCode::INVALID_ADDRESS))?;

    // Build the manifest only for the service GUID provided
    let service_guid = Uuid::from(&request.service_guid);
    let manifest = build_service_manifest_one(&service_guid)
        .ok_or_else(|| AttestationResult::from_code(SvsmResultCode::INVALID_PARAMETER))?;

    request.base.attest_service_manifest(&manifest)
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