/* SPDX-License-Identifier: MIT */
/*
 * Copyright (C) 2023 IBM Corporation
 *
 * Authors: Claudio Carvalho <cclaudio@linux.ibm.com>
 *          Dov Murik <dovmurik@linux.ibm.com>
 */

extern crate alloc;

use crate::locking::SpinLock;

use alloc::vec::Vec;
use core::ptr::addr_of;
use core::{mem::size_of, cell::OnceCell};
use core::slice::from_raw_parts;
use core::str::FromStr;
use crate::fw_meta::Uuid;

const SERVICES_MANIFEST_GUID: &str = "63849ebb-3d92-4670-a1ff-58f9c94b87bb";

/// Global registry of services
static SERVICES: SpinLock<OnceCell<Services>> = SpinLock::new(OnceCell::new());

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
//#[allow(dead_code)]
#[repr(C, packed)]
struct ManifestHeader {
    guid: Uuid,
    size: u32,
    num_services: u32,
}

impl ManifestHeader {
    pub fn as_slice(&self) -> &[u8] {
        let ptr: *const u8 = addr_of!(self).cast::<u8>();
        unsafe { from_raw_parts(ptr, size_of::<Self>()) }
    }
}

/// SVSM Spec Chapter 7 (Attestation): Table 12: Services Manifest
//#[allow(dead_code)]
#[repr(C, packed)]
struct ServiceEntry {
    guid: Uuid,
    data_offset: u32,
    data_size: u32,
}

impl ServiceEntry {
    pub fn as_slice(&self) -> &[u8] {
        let ptr: *const u8 = addr_of!(self).cast::<u8>();
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
    pub fn register(&mut self, guid: &Uuid, data: &[u8]) -> Result<(), ()> {
        if self.get_service(guid).is_some() {
            return Err(());
        }
        self.data_size += data.len();
        self.list.push(Service {
            guid: *guid,
            data: data.to_vec(),
        });
        Ok(())
    }

    /// Return the service identified by @guid, otherwise None.
    fn get_service(&self, guid: &Uuid) -> Option<&Service> {
        for service in self.list.iter() {
            if service.guid == *guid {
                return Some(service);
            }
        }
        None
    }

    /// Build a manifest with only the service entry identified by @guid.
    /// None is returned if the @guid is not registered.
    pub fn build_manifest_one(&self, guid: &Uuid) -> Option<Vec<u8>> {
        let Some(service) = self.get_service(guid) else {
            return None;
        };

        let start_data_offset: usize = size_of::<ManifestHeader>() + size_of::<ServiceEntry>();
        let service_entry = ServiceEntry {
            guid: service.guid,
            data_offset: start_data_offset as u32,
            data_size: service.data.len() as u32,
        };

        let mut service_entries = Vec::<u8>::with_capacity(size_of::<ServiceEntry>());
        service_entries.extend_from_slice(service_entry.as_slice());

        let mut data_entries = Vec::<u8>::with_capacity(service.data.len());
        data_entries.extend_from_slice(&service.data);

        let manifest_size: usize = size_of::<ManifestHeader>()
            + service_entries.len()
            + data_entries.len();

        let manifest_guid = Uuid::from_str(SERVICES_MANIFEST_GUID)
            .expect("Failed to convert the Service Manifest GUID");

        let manifest_header = ManifestHeader {
            guid: manifest_guid,
            size: manifest_size as u32,
            num_services: 1,
        };

        let mut manifest = Vec::<u8>::with_capacity(manifest_size);
        manifest.extend_from_slice(manifest_header.as_slice());
        manifest.extend_from_slice(&service_entries);
        manifest.extend_from_slice(&data_entries);
        Some(manifest)
    }

    /// Build a manifest with all service entries registered
    pub fn build_manifest_all(&self) -> Vec<u8> {
        let services_entries_size: usize = size_of::<ServiceEntry>() * self.list.len();
        let start_data_offset: usize = size_of::<ManifestHeader>() + services_entries_size;

        let mut service_entries = Vec::<u8>::with_capacity(services_entries_size);
        let mut data_entries = Vec::<u8>::with_capacity(self.data_size);

        for service in self.list.iter() {
            let service_entry = ServiceEntry {
                guid: service.guid,
                data_offset: (start_data_offset + data_entries.len()) as u32,
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

    // /// Serialize the services manifest.  Set `single_service_guid` to `None` to
    // /// include all services in the manifest, or to `Some(guid)` to include only
    // /// a single service.
    // pub fn build_manifest(
    //     &self,
    //     single_service_guid: Option<Uuid>,
    //     _manifest_version: Option<u32>,
    // ) -> Vec<u8> {
    //     let data_start_offset: usize = size_of::<ManifestHeader>()
    //     data_start_offset += 
    //         + (size_of::<ServiceEntry>() as usize * self.list.len());

    //     let mut service_entries: Vec<u8> = Vec::new();
    //     let mut data: Vec<u8> = Vec::new();

    //     for service in &self.list {
    //         if let Some(filter_guid) = single_service_guid {
    //             if service.guid != filter_guid {
    //                 continue;
    //             }
    //         }
    //         let entry: ServiceEntry = ServiceEntry {
    //             guid: service.guid.to_bytes_le(),
    //             data_offset: (data_start_offset + data.len()) as u32,
    //             data_size: service.data.len() as u32,
    //         };
    //         service_entries.extend_from_slice(entry.as_bytes());
    //         data.extend_from_slice(&service.data);
    //     }

    //     let total_size: usize =
    //         size_of::<ManifestHeader>() as usize + service_entries.len() + data.len();
    //     let header: ManifestHeader = ManifestHeader {
    //         guid: SERVICES_MANIFEST_HEADER_UUID.to_bytes_le(),
    //         size: total_size as u32,
    //         num_services: self.list.len() as u32,
    //     };
    //     let mut res: Vec<u8> = Vec::with_capacity(total_size);
    //     res.extend_from_slice(header.as_bytes());
    //     res.extend_from_slice(&service_entries);
    //     res.extend_from_slice(&data);
    //     res
    // }
}

pub fn protocols_init_services() {
    let _ = SERVICES.lock().get_or_init(|| Services::new());

    // vTPM init
    //vtpm_init();
}

pub fn protocols_register_service(guid: &Uuid, data: &[u8]) -> Result<(), ()> {
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
    use super::*;

    #[test]
    pub fn test_serialize_empty_manifest() {
        let s: Services = Services::new();
        let b: Vec<u8> = s.build_manifest(None, None);
        assert_eq!(b.len(), 24);
    }

    #[test]
    pub fn test_serialize_manifest_with_services_and_data() {
        let mut s: Services = Services::new();
        s.add_service(
            uuid!("11112222-1234-5678-9abc-ddddeeeeffff"),
            b"TheServiceData",
        );
        s.add_service(
            uuid!("88889999-8888-9999-8888-999988889999"),
            b"OtherServiceData",
        );
        let b: Vec<u8> = s.build_manifest(None, None);
        assert_eq!(b.len(), 24 + 24 + 24 + 14 + 16);
        assert_eq!(&b[72..86], b"TheServiceData");
        assert_eq!(&b[86..], b"OtherServiceData");
    }

    #[test]
    pub fn test_serialize_single_service_manifest() {
        let mut s: Services = Services::new();
        s.add_service(
            uuid!("11112222-1234-5678-9abc-ddddeeeeffff"),
            b"TheServiceData",
        );
        s.add_service(
            uuid!("88889999-8888-9999-8888-999988889999"),
            b"OtherServiceData",
        );
        let b: Vec<u8> = s.build_manifest(Some(uuid!("11112222-1234-5678-9abc-ddddeeeeffff")), None);
        assert_eq!(b.len(), 24 + 24 + 14);
        assert_eq!(&b[48..], b"TheServiceData");
    }
}
