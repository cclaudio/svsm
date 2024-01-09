// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM Corporation
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
//          Dov Murik <dovmurik@linux.ibm.com>

extern crate alloc;

use alloc::vec::Vec;
use core::{
    cell::OnceCell,
    mem::size_of,
    ptr::addr_of,
    slice::from_raw_parts,
    str::FromStr,
};
use crate::{
    locking::SpinLock,
    protocols::errors::SvsmReqError,
    utils::uuid::Uuid,
};

const SERVICES_MANIFEST_GUID: &str = "63849ebb-3d92-4670-a1ff-58f9c94b87bb";

/// Global registry of services
static SERVICES: SpinLock<OnceCell<Services>> = SpinLock::new(OnceCell::new());

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
#[repr(C, packed)]
struct ManifestHeader {
    guid: Uuid,
    size: u32,
    num_services: u32,
}

impl ManifestHeader {
    pub fn as_slice(&self) -> &[u8] {
        let ptr: *const u8 = addr_of!(*self).cast::<u8>();
        unsafe { from_raw_parts(ptr, size_of::<Self>()) }
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
#[repr(C, packed)]
struct ServiceEntry {
    guid: Uuid,
    data_offset: u32,
    data_size: u32,
}

impl ServiceEntry {
    pub fn as_slice(&self) -> &[u8] {
        let ptr: *const u8 = addr_of!(*self).cast::<u8>();
        unsafe { from_raw_parts(ptr, size_of::<Self>()) }
    }
}

struct Service {
    guid: Uuid,
    data: Vec<u8>,
}

struct Services {
    data_size: usize,
    list: Vec<Service>,
}

impl Services {
    pub const fn new() -> Self {
        Services { list: Vec::<Service>::new() , data_size: 0 }
    }

    /// Register a new service. If the service is already registered, an empty error
    /// is returned.
    pub fn register(&mut self, guid: Uuid, data: Vec<u8>) -> Result<(), SvsmReqError> {
        if self.get_service(&guid).is_some() {
            return Err(SvsmReqError::invalid_parameter());
        }
        self.data_size += data.len();
        self.list.push(Service { guid, data });
        Ok(())
    }

    /// Return the service identified by @guid, otherwise None.
    fn get_service(&self, guid: &Uuid) -> Option<&Service> {
        self.list.iter().find(|s| s.guid == *guid)
    }

    /// Build a manifest with only the service entry identified by @guid.
    /// None is returned if the @guid is not registered.
    pub fn build_manifest_one(&self, guid: &Uuid) -> Option<Vec<u8>> {
        let Some(service) = self.get_service(guid) else {
            return None;
        };

        let manifest_guid = Uuid::from_str(SERVICES_MANIFEST_GUID)
            .expect("Failed to convert the Service Manifest GUID");

        let data_offset_start: usize = size_of::<ManifestHeader>() + size_of::<ServiceEntry>();
        let manifest_size: usize = data_offset_start + service.data.len();

        let manifest_header = ManifestHeader {
            guid: manifest_guid,
            size: manifest_size as u32,
            num_services: 1,
        };

        let service_entry = ServiceEntry {
            guid: service.guid,
            data_offset: data_offset_start as u32,
            data_size: service.data.len() as u32,
        };

        let mut manifest = Vec::<u8>::with_capacity(manifest_size);
        manifest.extend_from_slice(manifest_header.as_slice());
        manifest.extend_from_slice(service_entry.as_slice());
        manifest.extend_from_slice(service.data.as_slice());

        Some(manifest)
    }

    /// Build a manifest with all service entries registered
    pub fn build_manifest_all(&self) -> Vec<u8> {
        let services_entries_size: usize = size_of::<ServiceEntry>() * self.list.len();
        let data_offset_start: usize = size_of::<ManifestHeader>() + services_entries_size;

        let mut service_entries = Vec::<u8>::with_capacity(services_entries_size);
        let mut data_entries = Vec::<u8>::with_capacity(self.data_size);

        for service in self.list.iter() {
            let service_entry = ServiceEntry {
                guid: service.guid,
                data_offset: (data_offset_start + data_entries.len()) as u32,
                data_size: service.data.len() as u32,
            };
            service_entries.extend_from_slice(service_entry.as_slice());
            data_entries.extend_from_slice(service.data.as_slice());
        }

        let manifest_size: usize = size_of::<ManifestHeader>()
            + service_entries.len()
            + data_entries.len();

        let manifest_guid = Uuid::from_str(SERVICES_MANIFEST_GUID)
            .expect("Failed to convert the Service Manifest GUID");
        
        let manifest_header = ManifestHeader {
            guid: manifest_guid,
            size: manifest_size as u32,
            num_services: service_entries.len() as u32,
        };

        let mut manifest = Vec::<u8>::with_capacity(manifest_size);
        manifest.extend_from_slice(manifest_header.as_slice());
        manifest.extend_from_slice(&service_entries);
        manifest.extend_from_slice(&data_entries);
        manifest
    }
}

pub fn protocols_init_services() {
    let _ = SERVICES.lock().get_or_init(|| Services::new());

    // Register the SVSM Protocol services always in the same order
    // to ensure the SHA512 hash of the manifest would be reproducible
    // for the same set of services.
}

pub fn protocols_register_service(guid: Uuid, data: Vec<u8>) -> Result<(), SvsmReqError> {
    SERVICES.lock().get_mut().unwrap().register(guid, data)
}

pub fn build_service_manifest_one(guid: &Uuid) -> Option<Vec<u8>> {
    SERVICES.lock().get().unwrap().build_manifest_one(guid)
}

pub fn build_service_manifest_all() -> Vec<u8> {
    SERVICES.lock().get().unwrap().build_manifest_all()
}

#[cfg(test)]
mod tests {
    use crate::protocols::{
        errors::SvsmReqError,
        services_manifest::{Services, Uuid},
    };

    extern crate alloc;

    use alloc::vec::Vec;
    use core::str::FromStr;

    const SERVICE1_GUID: &str = "11112222-1234-5678-9abc-ddddeeeeffff";
    const SERVICE2_GUID: &str = "88889999-8888-9999-8888-999988889999";

    const SERVICE1_DATA: &[u8] = b"TheServiceData";
    const SERVICE2_DATA: &[u8] = b"OtherserviceData";

    fn new_initialized_services() -> Result<Services, SvsmReqError> {
        let guid1 = Uuid::from_str(SERVICE1_GUID)?;
        let guid2 = Uuid::from_str(SERVICE2_GUID)?;

        let data1: Vec<u8> = SERVICE1_DATA.to_vec();
        let data2: Vec<u8> = SERVICE2_DATA.to_vec();

        let mut s = Services::new();
        s.register(guid1, data1)?;
        s.register(guid2, data2)?;
        Ok(s)
    }

    #[test]
    pub fn test_serialize_empty_manifest() {
        let s = Services::new();
        let m: Vec<u8> = s.build_manifest_all();
        assert_eq!(m.len(), 24);
    }

    #[test]
    pub fn test_serialize_manifest_with_services_and_data() {
        let s: Services = new_initialized_services().unwrap();
        let m: Vec<u8> = s.build_manifest_all();
        assert_eq!(m.len(), 24 + 24 + 24 + 14 + 16);
        assert_eq!(&m[72..86], SERVICE1_DATA);
        assert_eq!(&m[86..], SERVICE2_DATA);
    }

    #[test]
    pub fn test_serialize_single_service_manifest() {
        let guid1 = Uuid::from_str(SERVICE1_GUID).unwrap();

        let s: Services = new_initialized_services().unwrap();
        let m: Vec<u8> = s.build_manifest_one(&guid1).unwrap();

        assert_eq!(m.len(), 24 + 24 + 14);
        assert_eq!(&m[48..], SERVICE1_DATA);
    }
}
