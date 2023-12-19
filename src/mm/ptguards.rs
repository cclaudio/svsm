// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use super::pagetable::PTEntryFlags;
use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::percpu::this_cpu_mut;
use crate::cpu::tlb::flush_address_sync;
use crate::error::SvsmError;
use crate::mm::virtualrange::{
    virt_alloc_range_2m, virt_alloc_range_4k, virt_free_range_2m, virt_free_range_4k,
};
use crate::types::{PAGE_SIZE, PAGE_SIZE_2M};

use crate::utils::MemoryRegion;

#[derive(Debug)]
#[must_use = "if unused the mapping will immediately be unmapped"]
pub struct PerCPUPageMappingGuard {
    mapping: MemoryRegion<VirtAddr>,
    huge: bool,
}

impl PerCPUPageMappingGuard {
    pub fn create(
        paddr_start: PhysAddr,
        paddr_end: PhysAddr,
        alignment: usize,
    ) -> Result<Self, SvsmError> {
        let align_mask = (PAGE_SIZE << alignment) - 1;
        let size = paddr_end - paddr_start;
        assert!((size & align_mask) == 0);
        assert!((paddr_start.bits() & align_mask) == 0);
        assert!((paddr_end.bits() & align_mask) == 0);

        let flags = PTEntryFlags::data();
        let huge = ((paddr_start.bits() & (PAGE_SIZE_2M - 1)) == 0)
            && ((paddr_end.bits() & (PAGE_SIZE_2M - 1)) == 0);
        let vaddr = if huge {
            let vaddr = virt_alloc_range_2m(size, 0)?;
            if let Err(e) =
                this_cpu_mut()
                    .get_pgtable()
                    .map_region_2m(vaddr, vaddr + size, paddr_start, flags)
            {
                virt_free_range_2m(vaddr, size);
                return Err(e);
            }
            vaddr
        } else {
            let vaddr = virt_alloc_range_4k(size, 0)?;
            if let Err(e) =
                this_cpu_mut()
                    .get_pgtable()
                    .map_region_4k(vaddr, vaddr + size, paddr_start, flags)
            {
                virt_free_range_4k(vaddr, size);
                return Err(e);
            }
            vaddr
        };

        let raw_mapping = MemoryRegion::new(vaddr, size);

        Ok(PerCPUPageMappingGuard {
            mapping: raw_mapping,
            huge,
        })
    }

    pub fn create_4k(paddr: PhysAddr) -> Result<Self, SvsmError> {
        Self::create(paddr, paddr + PAGE_SIZE, 0)
    }

    pub fn virt_addr(&self) -> VirtAddr {
        self.mapping.start()
    }

    pub fn len(&self) -> usize {
        self.mapping.len()
    }
}

impl Drop for PerCPUPageMappingGuard {
    fn drop(&mut self) {
        let start = self.mapping.start();
        let end = self.mapping.end();
        let size = self.mapping.len();

        if self.huge {
            this_cpu_mut().get_pgtable().unmap_region_2m(start, end);
            virt_free_range_2m(start, size);
        } else {
            this_cpu_mut().get_pgtable().unmap_region_4k(start, end);
            virt_free_range_4k(start, size);
        }
        flush_address_sync(start);
    }
}
