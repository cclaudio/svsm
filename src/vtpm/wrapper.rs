// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (C) 2023 IBM
//
// Authors: Claudio Carvalho <cclaudio@linux.ibm.com>

/// This crate implements the C wrappers required to build the libvtpm.a dependencies
use crate::console::_print;
use crate::mm::alloc::{
    layout_from_ptr, layout_from_size, mem_allocate, mem_deallocate, mem_reallocate,
};
use crate::sev::msr_protocol::request_termination_msr;

use core::alloc::Layout;
use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use core::slice::from_raw_parts;
use core::str::from_utf8;

#[no_mangle]
pub extern "C" fn malloc(size: c_ulong) -> *mut c_void {
    let layout: Layout = layout_from_size(size as usize);
    mem_allocate(layout) as *mut c_void
}

#[no_mangle]
pub extern "C" fn calloc(items: c_ulong, size: c_ulong) -> *mut c_void {
    if let Some(new_size) = items.checked_mul(size as u64) {
        return malloc(new_size);
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn realloc(p: *mut c_void, size: c_ulong) -> *mut c_void {
    let ptr = p as *mut u8;
    let new_size = size as usize;
    if let Some(layout) = layout_from_ptr(ptr) {
        return unsafe { mem_reallocate(ptr, layout, new_size) as *mut c_void };
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    let ptr = p as *mut u8;
    if let Some(layout) = layout_from_ptr(ptr) {
        unsafe { mem_deallocate(ptr, layout) }
    }
}

#[no_mangle]
pub extern "C" fn serial_out(s: *const c_char, size: c_int) {
    let str_slice: &[u8] = unsafe { from_raw_parts(s as *const u8, size as usize) };
    if let Ok(rust_str) = from_utf8(str_slice) {
        _print(format_args!("[SVSM] {}", rust_str));
    } else {
        log::error!("ERR: BUG: serial_out arg1 is not a valid utf8 string");
    }
}

#[no_mangle]
pub extern "C" fn abort() -> ! {
    request_termination_msr();
}
