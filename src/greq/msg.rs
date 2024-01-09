// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

//! Message that carries an encrypted `SNP_GUEST_REQUEST` command in the payload

extern crate alloc;

use alloc::{
    alloc::{alloc_zeroed, Layout},
    boxed::Box, vec::Vec,
};
use core::{
    mem::size_of,
    ptr::{addr_of, addr_of_mut, copy_nonoverlapping},
    slice::{from_raw_parts, from_raw_parts_mut, from_ref},
};

use crate::{
    address::{Address, VirtAddr},
    cpu::percpu::this_cpu_mut,
    crypto::aead::{Aes256Gcm, Aes256GcmTrait, AUTHTAG_SIZE},
    mm::virt_to_phys,
    protocols::errors::SvsmReqError,
    sev::{ghcb::PageStateChangeOp, secrets_page::VMPCK_SIZE},
    types::{PageSize, PAGE_SIZE}, utils::uuid::Uuid,
};

/// Version of the message header
const HDR_VERSION: u8 = 1;
/// Version of the message payload
const MSG_VERSION: u8 = 1;

/// AEAD Algorithm Encodings (AMD SEV-SNP spec. table 99)
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SnpGuestRequestAead {
    Invalid = 0,
    Aes256Gcm = 1,
}

/// Message Type Encodings (AMD SEV-SNP spec. table 100)
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(u8)]
pub enum SnpGuestRequestMsgType {
    Invalid = 0,
    ReportRequest = 5,
    ReportResponse = 6,
}

impl TryFrom<u8> for SnpGuestRequestMsgType {
    type Error = SvsmReqError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            x if x == Self::Invalid as u8 => Ok(Self::Invalid),
            x if x == Self::ReportRequest as u8 => Ok(Self::ReportRequest),
            x if x == Self::ReportResponse as u8 => Ok(Self::ReportResponse),
            _ => Err(SvsmReqError::invalid_parameter()),
        }
    }
}

/// Message header size
const MSG_HDR_SIZE: usize = size_of::<SnpGuestRequestMsgHdr>();
/// Message payload size
const MSG_PAYLOAD_SIZE: usize = PAGE_SIZE - MSG_HDR_SIZE;

/// Maximum buffer size that the hypervisor takes to store the
/// SEV-SNP certificates
pub const SNP_GUEST_REQ_MAX_DATA_SIZE: usize = 4 * PAGE_SIZE;

/// `SNP_GUEST_REQUEST` message header format (AMD SEV-SNP spec. table 98)
#[repr(C, packed)]
#[derive(Copy, Clone, Debug)]
pub struct SnpGuestRequestMsgHdr {
    /// Message authentication tag
    authtag: [u8; 32],
    /// The sequence number for this message
    msg_seqno: u64,
    /// Reserve. Must be zero.
    rsvd1: [u8; 8],
    /// The AEAD used to encrypt this message
    algo: u8,
    /// The version of the message header
    hdr_version: u8,
    /// The size of the message header in bytes
    hdr_sz: u16,
    /// The type of the payload
    msg_type: u8,
    /// The version of the payload
    msg_version: u8,
    /// The size of the payload in bytes
    msg_sz: u16,
    /// Reserved. Must be zero.
    rsvd2: u32,
    /// The ID of the VMPCK used to protect this message
    msg_vmpck: u8,
    /// Reserved. Must be zero.
    rsvd3: [u8; 35],
}

const _: () = assert!(size_of::<SnpGuestRequestMsgHdr>() <= u16::MAX as usize);

impl SnpGuestRequestMsgHdr {
    /// Allocate a new [`SnpGuestRequestMsgHdr`] and initialize it
    pub fn new(msg_sz: u16, msg_type: SnpGuestRequestMsgType, msg_seqno: u64) -> Self {
        Self {
            msg_seqno,
            algo: SnpGuestRequestAead::Aes256Gcm as u8,
            hdr_version: HDR_VERSION,
            hdr_sz: MSG_HDR_SIZE as u16,
            msg_type: msg_type as u8,
            msg_version: MSG_VERSION,
            msg_sz,
            msg_vmpck: 0,
            ..Default::default()
        }
    }

    pub fn copy_from(&mut self, src_hdr: &Self) {
        unsafe {
            copy_nonoverlapping(addr_of!(*src_hdr).cast::<u8>(), addr_of_mut!(*self).cast::<u8>(), size_of::<Self>());
        }
    }

    /// Set the authenticated tag
    fn set_authtag(&mut self, new_tag: &[u8]) -> Result<(), SvsmReqError> {
        self.authtag
            .get_mut(..new_tag.len())
            .ok_or_else(SvsmReqError::invalid_parameter)?
            .copy_from_slice(new_tag);
        Ok(())
    }

    /// Validate the [`SnpGuestRequestMsgHdr`] fields
    fn validate(
        &self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
    ) -> Result<(), SvsmReqError> {
        if self.hdr_version != HDR_VERSION
            || self.hdr_sz != MSG_HDR_SIZE as u16
            || self.algo != SnpGuestRequestAead::Aes256Gcm as u8
            || self.msg_type != msg_type as u8
            || self.msg_vmpck != 0
            || self.msg_seqno != msg_seqno
        {
            return Err(SvsmReqError::invalid_format());
        }
        Ok(())
    }

    /// Get a slice of the header fields used as additional authenticated data (AAD)
    fn get_aad_slice(&self) -> &[u8] {
        let self_gva = addr_of!(*self);
        let algo_gva = addr_of!(self.algo);
        let algo_offset = algo_gva as isize - self_gva as isize;

        let slice: &[Self] = from_ref(self);
        let ptr: *const Self = slice.as_ptr();
        // SAFETY: we are doing:
        // &[Self] -> *const Self -> *const u8 -> &[u8]
        // This is safe as it simply reinterprets the underlying type as bytes
        // by using the &self borrow. This is safe because Self has no invalid
        // representations, as it is composed of simple integer types.
        // &[u8] has no alignment requirements, and this new slice has the
        // same size as Self, so we are within bounds.
        let b = unsafe { from_raw_parts(ptr.cast::<u8>(), size_of::<Self>()) };

        &b[algo_offset as usize..]
    }

    /// Get [`SnpGuestRequestMsgHdr`] as a mutable slice reference
    fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { from_raw_parts_mut(addr_of_mut!(*self).cast(), size_of::<Self>()) }
    }
}

impl Default for SnpGuestRequestMsgHdr {
    /// default() method implementation. We can't derive Default because
    /// the field "rsvd3: [u8; 35]" conflicts with the Default trait, which
    /// supports up to [T; 32].
    fn default() -> Self {
        Self {
            authtag: [0; 32],
            msg_seqno: 0,
            rsvd1: [0; 8],
            algo: 0,
            hdr_version: 0,
            hdr_sz: 0,
            msg_type: 0,
            msg_version: 0,
            msg_sz: 0,
            rsvd2: 0,
            msg_vmpck: 0,
            rsvd3: [0; 35],
        }
    }
}

/// `SNP_GUEST_REQUEST` message format
#[repr(C, align(4096))]
#[derive(Debug)]
pub struct SnpGuestRequestMsg {
    hdr: SnpGuestRequestMsgHdr,
    pld: [u8; MSG_PAYLOAD_SIZE],
}

// The GHCB spec says it has to fit in one page and be page aligned
const _: () = assert!(size_of::<SnpGuestRequestMsg>() <= PAGE_SIZE);

impl SnpGuestRequestMsg {
    /// Allocate the object in the heap without going through stack as
    /// this is a large object
    ///
    /// # Panics
    ///
    /// Panics if the new allocation is not page aligned.
    pub fn boxed_new() -> Result<Box<Self>, SvsmReqError> {
        let layout = Layout::new::<Self>();

        unsafe {
            let addr = alloc_zeroed(layout);
            if addr.is_null() {
                return Err(SvsmReqError::invalid_request());
            }

            assert!(VirtAddr::from(addr).is_page_aligned());

            let ptr = addr.cast::<Self>();
            Ok(Box::from_raw(ptr))
        }
    }

    pub fn copy_from(&mut self, src_msg: &Self) {
        unsafe {
            copy_nonoverlapping(addr_of!(*src_msg).cast::<u8>(), addr_of_mut!(*self).cast::<u8>(), size_of::<Self>());
        }
    }

    /// Clear the C-bit (memory encryption bit) for the Self page
    ///
    /// # Safety
    ///
    /// * The caller is responsible for setting the page back to encrypted
    ///   before the object is dropped. Shared pages should not be freed
    ///   (returned to the allocator)
    pub fn set_shared(&mut self) -> Result<(), SvsmReqError> {
        let vaddr = VirtAddr::from(addr_of!(*self));
        this_cpu_mut()
            .get_pgtable()
            .set_shared_4k(vaddr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(vaddr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscShared,
            )
            .map_err(|_| SvsmReqError::invalid_request())
    }

    /// Set the C-bit (memory encryption bit) for the Self page
    pub fn set_encrypted(&mut self) -> Result<(), SvsmReqError> {
        let vaddr = VirtAddr::from(addr_of!(*self));
        this_cpu_mut()
            .get_pgtable()
            .set_encrypted_4k(vaddr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(vaddr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscPrivate,
            )
            .map_err(|_| SvsmReqError::invalid_request())
    }

    pub fn set_payload(&mut self, payload: &[u8]) -> Result<(), SvsmReqError> {
        self.pld.fill(0);
        self.pld
            .get_mut(..payload.len())
            .ok_or_else(SvsmReqError::invalid_request)?
            .copy_from_slice(payload);
        Ok(())
    }

    /// Fill the [`SnpGuestRequestMsg`] fields with zeros
    pub fn clear(&mut self) {
        self.hdr.as_slice_mut().fill(0);
        self.pld.fill(0);
    }

    /// Encrypt the provided `SNP_GUEST_REQUEST` command and store the result in the actual message payload
    ///
    /// The command will be encrypted using AES-256 GCM and part of the message header will be
    /// used as additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `msg_type`: Type of the command stored in the `command` buffer.
    /// * `msg_seqno`: VMPL0 sequence number to be used in the message. The PSP will reject
    ///                subsequent messages when it detects that the sequence numbers are
    ///                out of sync. The sequence number is also used as initialization
    ///                vector (IV) in encryption.
    /// * `vmpck0`: VMPCK0 key that will be used to encrypt the command.
    /// * `command`: command slice to be encrypted.
    ///
    /// # Returns
    ///
    /// () on success and [`SvsmReqError`] on error.
    ///
    /// # Panic
    ///
    /// * The command length does not fit in a u16
    /// * The encrypted and the original command don't have the same size
    pub fn encrypt_set(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
        command: &[u8],
    ) -> Result<(), SvsmReqError> {
        let payload_size_u16 =
            u16::try_from(command.len()).map_err(|_| SvsmReqError::invalid_parameter())?;

        let mut msg_hdr = SnpGuestRequestMsgHdr::new(payload_size_u16, msg_type, msg_seqno);
        let aad: &[u8] = msg_hdr.get_aad_slice();
        let iv: Vec<u8> = build_iv(msg_seqno);

        // Encrypt the provided command and return the ciphertext+authtag in a vector
        let buffer: Vec<u8> = Aes256Gcm::encrypt(iv.as_slice(), vmpck0, aad, command)?;
        let ciphertext_end: usize = buffer
            .len()
            .checked_sub(AUTHTAG_SIZE)
            .ok_or_else(SvsmReqError::invalid_request)?;
        // The command should have the same size when encrypted and decrypted
        if ciphertext_end != command.len() {
            return Err(SvsmReqError::invalid_request());
        }
        let (ciphertext, authtag) = buffer.split_at(ciphertext_end);
        msg_hdr.set_authtag(authtag)?;
        self.hdr.copy_from(&msg_hdr);
        self.set_payload(ciphertext)?;
        Ok(())
    }

    /// Decrypt the `SNP_GUEST_REQUEST` command stored in the message and store the decrypted command in
    /// the provided `outbuf`.
    ///
    /// The command stored in the message payload is usually a response command received from the PSP.
    /// It will be decrypted using AES-256 GCM and part of the message header will be used as
    /// additional authenticated data (AAD).
    ///
    /// # Arguments
    ///
    /// * `msg_type`: Type of the command stored in the message payload
    /// * `msg_seqno`: VMPL0 sequence number that was used in the message.
    /// * `vmpck0`: VMPCK0 key, it will be used to decrypt the message
    ///
    /// # Returns
    ///
    /// * Success
    ///     * Vec<u8>: Decrypted [`SnpGuestRequestMsg`] pld
    /// * Error
    ///     * [`SvsmReqError`]
    pub fn decrypt_get(
        &mut self,
        msg_type: SnpGuestRequestMsgType,
        msg_seqno: u64,
        vmpck0: &[u8; VMPCK_SIZE],
    ) -> Result<Vec<u8>, SvsmReqError> {
        self.hdr.validate(msg_type, msg_seqno)?;
        let iv: Vec<u8> = build_iv(msg_seqno);
        let aad: &[u8] = self.hdr.get_aad_slice();
        let ciphertext_len = usize::from(self.hdr.msg_sz);
        let ciphertext = self.pld
            .get(..ciphertext_len)
            .ok_or_else(SvsmReqError::invalid_request)?;
        let authtag = self.hdr
            .authtag
            .get(..AUTHTAG_SIZE)
            .ok_or_else(SvsmReqError::invalid_request)?;
        let mut postfix = Vec::<u8>::with_capacity(ciphertext_len + AUTHTAG_SIZE);
        postfix.extend_from_slice(ciphertext);
        postfix.extend_from_slice(authtag);

        Aes256Gcm::decrypt(iv.as_slice(), vmpck0, aad, postfix.as_slice())
    }
}

/// Build the initialization vector for AES-256 GCM. The SVSM spec says it has to be 96-bits (12 bytes)
fn build_iv(msg_seqno: u64) -> Vec<u8> {
    let mut iv = Vec::<u8>::with_capacity(size_of::<u64>());
    iv.extend_from_slice(&msg_seqno.to_ne_bytes());
    iv.extend_from_slice(&[0; 4]);
    iv
}

/// Set to encrypted all the 4k pages of a memory range
fn set_encrypted_region_4k(start: VirtAddr, end: VirtAddr) -> Result<(), SvsmReqError> {
    for addr in (start.bits()..end.bits())
        .step_by(PAGE_SIZE)
        .map(VirtAddr::from)
    {
        this_cpu_mut()
            .get_pgtable()
            .set_encrypted_4k(addr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(addr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscPrivate,
            )
            .map_err(|_| SvsmReqError::invalid_request())?;
    }
    Ok(())
}

/// Set to shared all the 4k pages of a memory range
fn set_shared_region_4k(start: VirtAddr, end: VirtAddr) -> Result<(), SvsmReqError> {
    for addr in (start.bits()..end.bits())
        .step_by(PAGE_SIZE)
        .map(VirtAddr::from)
    {
        this_cpu_mut()
            .get_pgtable()
            .set_shared_4k(addr)
            .map_err(|_| SvsmReqError::invalid_request())?;

        let paddr = virt_to_phys(addr);
        this_cpu_mut()
            .ghcb()
            .page_state_change(
                paddr,
                paddr + PAGE_SIZE,
                PageSize::Regular,
                PageStateChangeOp::PscShared,
            )
            .map_err(|_| SvsmReqError::invalid_request())?;
    }
    Ok(())
}

/// Data page(s) the hypervisor will use to store certificate data in
/// an extended `SNP_GUEST_REQUEST`
#[repr(C, align(4096))]
#[derive(Debug)]
pub struct SnpGuestRequestExtData {
    /// According to the GHCB spec, the data page(s) must be contiguous pages if
    /// supplying more than one page and all certificate pages must be
    /// assigned to the hypervisor (shared).
    data: [u8; SNP_GUEST_REQ_MAX_DATA_SIZE],
}

/// The certificates returned in [`SnpGuestRequestExtData`] data are identified by
/// a table of [`CertTableEntry`] where:
///    - the table is terminated with an entry containing all zeros for the GUID,
///      offset and length
///    - Certificate data starts just after the table
#[derive(Debug)]
#[repr(C, packed)]
struct CertTableEntry {
    /// GUID of the Certificate
    guid: Uuid,
    /// Offset from the [`SnpGuestRequestExtData`] data to where the certificate
    /// data starts
    offset: u32,
    /// Length of the certificate data
    length: u32,
}

impl SnpGuestRequestExtData {
    /// Allocate the object in the heap without going through stack as
    /// this is a large object
    pub fn boxed_new() -> Result<Box<Self>, SvsmReqError> {
        let layout = Layout::new::<Self>();
        unsafe {
            let addr = alloc_zeroed(layout);
            if addr.is_null() {
                return Err(SvsmReqError::invalid_request());
            }
            assert!(VirtAddr::from(addr).is_page_aligned());

            let ptr = addr.cast::<Self>();
            Ok(Box::from_raw(ptr))
        }
    }

    pub fn len(&self) -> Option<usize> {
        const TABLE_ENTRY_SIZE: usize = size_of::<CertTableEntry>();

        let start = VirtAddr::from(self.data.as_ptr());
        let end = start + SNP_GUEST_REQ_MAX_DATA_SIZE;

        let mut max_offset: u32 = 0;
        let mut entry_len: u32 = 0;
        
        for vaddr in (start.bits()..end.bits())
            .step_by(TABLE_ENTRY_SIZE)
            .map(VirtAddr::from)
        {
            let entry = unsafe { &*vaddr.as_ptr::<CertTableEntry>() };
            
            if entry.offset > max_offset {
                max_offset = entry.offset;
                entry_len = entry.length;
            }

            if entry.guid.is_zeroed() {
                let certs_len: usize = (max_offset + entry_len) as usize;
                if certs_len < SNP_GUEST_REQ_MAX_DATA_SIZE {
                    return Some(certs_len);
                } else {
                    return None;
                }
            }
        }
        None
    }

    pub fn get_certificates(&self) -> Option<Vec<u8>> {
        let Some(len) = self.len() else {
            return None;
        };

        if len == 0 {
            Some(Vec::<u8>::new())
        } else {
            let mut certs = Vec::<u8>::with_capacity(len);
            certs.extend_from_slice(&self.data[..len]);
            Some(certs)
        }
    }

    /// Clear the C-bit (memory encryption bit) for the Self pages
    ///
    /// # Safety
    ///
    /// * The caller is responsible for setting the page back to encrypted
    ///   before the object is dropped. Shared pages should not be freed
    ///   (returned to the allocator)
    pub fn set_shared(&mut self) -> Result<(), SvsmReqError> {
        let start = VirtAddr::from(addr_of!(*self));
        let end = start + size_of::<Self>();
        set_shared_region_4k(start, end)
    }

    /// Set the C-bit (memory encryption bit) for the Self pages
    pub fn set_encrypted(&mut self) -> Result<(), SvsmReqError> {
        let start = VirtAddr::from(addr_of!(*self));
        let end = start + size_of::<Self>();
        set_encrypted_region_4k(start, end)
    }

    /// Clear the data
    pub fn clear(&mut self) {
        self.data.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::alloc::{TestRootMem, DEFAULT_TEST_MEMORY_SIZE};
    use crate::sev::secrets_page::VMPCK_SIZE;
    use memoffset::offset_of;

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "offset_of")]
    fn test_snp_guest_request_hdr_offsets() {
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, authtag), 0);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_seqno), 0x20);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd1), 0x28);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, algo), 0x30);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, hdr_version), 0x31);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, hdr_sz), 0x32);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_type), 0x34);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_version), 0x35);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_sz), 0x36);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd2), 0x38);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, msg_vmpck), 0x3c);
        assert_eq!(offset_of!(SnpGuestRequestMsgHdr, rsvd3), 0x3d);
    }

    #[test]
    #[cfg_attr(test_in_svsm, ignore = "offset_of")]
    fn test_snp_guest_request_msg_offsets() {
        assert_eq!(offset_of!(SnpGuestRequestMsg, hdr), 0);
        assert_eq!(offset_of!(SnpGuestRequestMsg, pld), 0x60);
    }

    #[test]
    fn test_requestmsg_boxed_new() {
        let _mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let mut data = SnpGuestRequestMsg::boxed_new().unwrap();
        assert!(data.hdr.as_slice_mut().iter().all(|c| *c == 0));
        assert!(data.pld.iter().all(|c| *c == 0));
    }

    #[test]
    fn test_reqextdata_boxed_new() {
        let _mem = TestRootMem::setup(DEFAULT_TEST_MEMORY_SIZE);
        let data = SnpGuestRequestExtData::boxed_new().unwrap();
        assert!(data.data.iter().all(|c| *c == 0));
    }

    #[test]
    fn aad_size() {
        let hdr = SnpGuestRequestMsgHdr::default();
        let aad = hdr.get_aad_slice();

        const HDR_ALGO_OFFSET: usize = 48;

        assert_eq!(aad.len(), MSG_HDR_SIZE - HDR_ALGO_OFFSET);
    }

    #[test]
    fn encrypt_decrypt_payload() {
        let mut msg = SnpGuestRequestMsg {
            hdr: SnpGuestRequestMsgHdr::default(),
            pld: [0; MSG_PAYLOAD_SIZE],
        };

        const REQUEST: &[u8] = b"request-to-be-encrypted";
        let vmpck0 = [5u8; VMPCK_SIZE];
        let vmpck0_seqno: u64 = 1;

        msg
            .encrypt_set(
                SnpGuestRequestMsgType::ReportRequest,
                vmpck0_seqno,
                &vmpck0,
                REQUEST,
            )
            .unwrap();

        let decrypted_request = msg
            .decrypt_get(
                SnpGuestRequestMsgType::ReportRequest,
                vmpck0_seqno,
                &vmpck0,
            )
            .unwrap();

        assert_eq!(decrypted_request, REQUEST);
    }
}
