// Copyright © 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![feature(alloc_error_handler)]
#![feature(asm, global_asm)]
#![feature(stmt_expr_attributes)]
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(test, allow(unused_imports, dead_code))]
#![cfg_attr(not(feature = "log-serial"), allow(unused_variables, unused_imports))]

use core::panic::PanicInfo;
use core::fmt::Write;

use x86_64::{
    instructions::hlt,
    registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags},
};
use sha2::Digest;
use crate::virtio::Error;
use bitflags::_core::cell::RefCell;
use crate::block::{AvailRing, UsedRing, Desc, BlockRequestHeader, RequestType, UsedElem};

#[macro_use]
mod serial;

#[macro_use]
mod common;

#[cfg(not(test))]
mod asm;
mod block;
mod boot;
mod bzimage;
mod coreboot;
mod delay;
mod efi;
mod fat;
mod gdt;
#[cfg(all(test, feature = "integration_tests"))]
mod integration;
mod loader;
mod mem;
mod paging;
mod part;
mod pci;
mod pe;
mod pvh;
mod rtc;
mod virtio;

#[cfg(all(not(test), feature = "log-panic"))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    log!("PANIC: {}", info);
    loop {
        hlt()
    }
}

#[cfg(all(not(test), not(feature = "log-panic")))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

// Enable SSE2 for XMM registers (needed for EFI calling)
fn enable_sse() {
    let mut cr0 = Cr0::read();
    cr0.remove(Cr0Flags::EMULATE_COPROCESSOR);
    cr0.insert(Cr0Flags::MONITOR_COPROCESSOR);
    unsafe { Cr0::write(cr0) };
    let mut cr4 = Cr4::read();
    cr4.insert(Cr4Flags::OSFXSR);
    cr4.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
    unsafe { Cr4::write(cr4) };
}

const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
const VIRTIO_PCI_BLOCK_DEVICE_ID: u16 = 0x1042;

fn boot_from_device(device: &mut block::VirtioBlockDevice, info: &dyn boot::Info) -> bool {
    if let Err(err) = device.init() {
        log!("Error configuring block device: {:?}", err);
        return false;
    }
    log!(
        "Virtio block device configured. Capacity: {} sectors",
        device.get_capacity()
    );

    let (start, end) = match part::find_efi_partition(device) {
        Ok(p) => p,
        Err(err) => {
            log!("Failed to find EFI partition: {:?}", err);
            return false;
        }
    };
    log!("Found EFI partition");

    let mut f = fat::Filesystem::new(device, start, end);
    if let Err(err) = f.init() {
        log!("Failed to create filesystem: {:?}", err);
        return false;
    }
    log!("Filesystem ready");

    match loader::load_default_entry(&f, info) {
        Ok(mut kernel) => {
            log!("Jumping to kernel");
            kernel.boot();
            return true;
        }
        Err(err) => log!("Error loading default entry: {:?}", err),
    }

    log!("Using EFI boot.");
    let mut file = match f.open("/EFI/BOOT/BOOTX64 EFI") {
        Ok(file) => file,
        Err(err) => {
            log!("Failed to load default EFI binary: {:?}", err);
            return false;
        }
    };
    log!("Found bootloader (BOOTX64.EFI)");

    let mut l = pe::Loader::new(&mut file);
    let load_addr = unsafe { (&unused_start as *const u8) as u64 };
    log!("EFI load address {:p}", load_addr as *const u8);
    let (entry_addr, load_addr, size) = match l.load(load_addr) {
        Ok(load_info) => load_info,
        Err(err) => {
            log!("Error loading executable: {:?}", err);
            return false;
        }
    };

    log!("Executable loaded");
    efi::efi_exec(entry_addr, load_addr, size, info, &f, device);
    true
}

#[no_mangle]
#[cfg(not(feature = "coreboot"))]
pub extern "C" fn rust64_start(rdi: &pvh::StartInfo) -> ! {
    serial::PORT.borrow_mut().init();

    enable_sse();
    paging::setup();

    main(rdi)
}

#[no_mangle]
#[cfg(feature = "coreboot")]
pub extern "C" fn rust64_start() -> ! {
    serial::PORT.borrow_mut().init();

    enable_sse();
    paging::setup();

    let info = coreboot::StartInfo::default();

    main(&info)
}

fn main(info: &dyn boot::Info) -> ! {
    log!("\nBooting with {}", info.name());

    let initial_efidisk = unsafe {
        let start_ptr: *const u8 = &_binary_efidisk_start;
        let end_ptr: *const u8 = &_binary_efidisk_end;
        let size = end_ptr.offset_from(start_ptr);
        core::slice::from_raw_parts(start_ptr, size as usize)
    };

    let new_address = (1024 as usize * (1 << 20)) as * mut u8;
    let efidisk = unsafe {
        let start_ptr: *mut u8 = new_address;
        let size = initial_efidisk.len();
        core::slice::from_raw_parts_mut(start_ptr, size as usize)
    };
    log!("Relocating EFI disk from {:p} to {:p}, size {}", initial_efidisk, efidisk, initial_efidisk.len());
    efidisk.copy_from_slice(initial_efidisk);

    // let efidisk = initial_efidisk;

    log!("EFI disk at {:p}: {}", efidisk.as_ptr(), efidisk.len());
    paging::mark_read_only(efidisk);

    // let efidisk_rom_slice = unsafe {
    //     let start_ptr: * const u8 = &rom_efidisk_start;
    //     let size = efidisk_ram_slice.len();
    //     core::slice::from_raw_parts(start_ptr, size as usize)
    // };
    //
    // unsafe { log!("data location: {:p}", &rom_data_start); }
    // unsafe { log!("UKI ROM location: {:p}", &rom_efidisk_start); }
    // unsafe { log!("pad start: {:p}", &pad_start); }

    let mut hasher = sha2::Sha256::default();
    hasher.update(&efidisk[0..]);
    log!("sha256 of RAM efidisk: {:02X?}", hasher.finalize());

    //
    // let mut hasher = sha2::Sha256::default();
    // hasher.update(&efidisk_rom_slice[0..1024]);
    // log!("sha256 of ROM efidisk: {:02X?}", hasher.finalize());

    let magic_range = unsafe {
        let start_ptr: *mut u8 = &mut magic_debug;
        let size = 2 * 1024 * 1024;
        core::slice::from_raw_parts_mut(start_ptr, size as usize)
    };

    magic_range[0..8].copy_from_slice(&(__debug_log as usize).to_le_bytes());

    let mut in_memory_transport = InMemoryVirtioTransport::new(efidisk);
    let mut device = block::VirtioBlockDevice::new(&mut in_memory_transport);
    let result = boot_from_device(&mut device, info);

    panic!("Unable to boot from EFI disk, result {}", result)
}

unsafe fn __debug_log(data: u8) {
    // let mut len = 0;
    // while *data.offset(len) != 0 {
    //     len += 1;
    // }
    // log!("{:x?}", core::slice::from_raw_parts(data, 16));
    // let slice = core::slice::from_raw_parts(data, len as usize);
    // log!("EFI __debug: {}", core::str::from_utf8_unchecked(slice));
    log!("EFI __debug: {}", data);
}

extern "C" {
    pub static _binary_efidisk_start: u8;
    pub static _binary_efidisk_end: u8;
    pub static unused_start: u8;
    pub static mut magic_debug: u8;
}

pub struct InMemoryVirtioTransport<'a> {
    data: &'a [u8],
    state: RefCell<InMemoryVirtioTransportState>,
}

struct InMemoryVirtioTransportState {
    disabled: bool,
    status: u32,
    features: u64,
    descriptors: Option<* const Desc>,
    avail_ring: Option<* const AvailRing>,
    used_ring: Option<* mut UsedRing>,
}

impl Default for InMemoryVirtioTransportState {
    fn default() -> Self {
        Self {
            disabled: false,
            status: 0,
            features: 1 << 32,
            descriptors: None,
            avail_ring: None,
            used_ring: None,
        }
    }
}

impl <'a> InMemoryVirtioTransport<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        InMemoryVirtioTransport {
            data,
            state: RefCell::new(InMemoryVirtioTransportState::default()),
        }
    }

    fn sector_count(&self) -> usize {
        self.data.len() / 512 + if self.data.len() % 512 > 0 { 1 } else { 0 }
    }

    fn get_desc(&self, index: u16) -> &Desc {
        unsafe { &*self.state.borrow().descriptors.unwrap().offset(index as isize) }
    }

    fn read_sector(&self, sector: usize, buffer: &mut [u8]) -> usize {
        let start = sector * 512;
        if start >= self.data.len() {
            panic!("Sector {} out of range", sector);
        }
        let end = core::cmp::min(start + 512, self.data.len());
        buffer.copy_from_slice(&self.data[start .. end]);
        end - start
    }

    fn disable(&self) {
        self.state.borrow_mut().disabled = true;
    }
}

impl <'a> crate::virtio::VirtioTransport for InMemoryVirtioTransport<'a> {
    fn init(&mut self, _device_type: u32) -> Result<(), Error> {
        log!("imvt init");
        Ok(())
    }

    fn get_status(&self) -> u32 {
        self.state.borrow().status
    }

    fn set_status(&self, status: u32) {
        self.state.borrow_mut().status = status;
    }

    fn add_status(&self, status: u32) {
        self.state.borrow_mut().status |= status;
    }

    fn reset(&self) {
        *self.state.borrow_mut() = InMemoryVirtioTransportState::default();
    }

    fn get_features(&self) -> u64 {
        self.state.borrow().features
    }

    fn set_features(&self, features: u64) {
        self.state.borrow_mut().features = features;
    }

    fn set_queue(&self, queue: u16) {
        log!("set_queue {}", queue);
    }

    fn get_queue_max_size(&self) -> u16 {
        16
    }

    fn set_queue_size(&self, queue_size: u16) {
        log!("set_queue_size {}", queue_size);
    }

    fn set_descriptors_address(&self, address: u64) {
        log!("set_descriptors_address {:x}", address);
        self.state.borrow_mut().descriptors.insert(address as * const Desc);
    }

    fn set_avail_ring(&self, address: u64) {
        log!("set_avail_ring {:x}", address);
        self.state.borrow_mut().avail_ring.insert(address as * const AvailRing);
    }

    fn set_used_ring(&self, address: u64) {
        log!("set_used_ring {:x}", address);
        self.state.borrow_mut().used_ring.insert(address as * mut UsedRing);
    }

    fn set_queue_enable(&self) {
        log!("set_queue_enable");
    }

    fn notify_queue(&self, queue: u16) {
        if self.state.borrow().disabled {
            panic!("memfs virtio transport disabled");
        }
        // log!("notify_queue {}", queue);

        let avail_ring = unsafe { &*self.state.borrow().avail_ring.unwrap() };
        let avail_index = (avail_ring.idx as usize + 16 - 1) % 16;
        let header_desc_index = avail_ring.ring[avail_index as usize];
        let header_desc = self.get_desc(header_desc_index);
        // log!("Header desc: {:?}", header_desc);

        if header_desc.flags & 1 == 0 {
            panic!("Expected VIRTQ_DESC_F_NEXT flag to be set in header desc");
        }

        let block_request_header = unsafe { &*(header_desc.addr as *const BlockRequestHeader) };
        // log!("Block request: {:?}", block_request_header);

        // We only handle Read requests
        if block_request_header.request != 0 {
            panic!("Refusing to handle request {}", block_request_header.request);
        }

        let write_buffer_desc_index = header_desc.next;
        let write_buffer_desc = self.get_desc(write_buffer_desc_index);
        // log!("Write buffer desc: {:?}", write_buffer_desc);
        if write_buffer_desc.flags & 1 == 0 {
            panic!("Expected VIRTQ_DESC_F_NEXT flag to be set in write buffer desc");
        }
        if write_buffer_desc.flags & 2 == 0 {
            panic!("Expected VIRTQ_DESC_F_WRITE flag to be set in write buffer desc");
        }
        let write_buffer_ptr = unsafe { &mut *(write_buffer_desc.addr as *mut u8) };
        // log!("Write buffer at {:p}", write_buffer_desc.addr as *mut u8);
        let write_buffer_len = write_buffer_desc.length;
        if write_buffer_len != 512 {
            panic!("Expected write buffer to be size 512");
        }
        let write_buffer = unsafe { core::slice::from_raw_parts_mut(write_buffer_ptr, write_buffer_len as usize) };
        let read_len = self.read_sector(block_request_header.sector as usize, write_buffer);
        // log!("Read {} bytes", read_len);

        let used_ring = unsafe { &mut *self.state.borrow().used_ring.unwrap() };
        // Use same indeces as the avail ring for simplicity
        used_ring.ring[avail_index as usize] = UsedElem {
            id: write_buffer_desc_index as u32,
            len: read_len as u32,
        };
        used_ring.idx = avail_ring.idx;
    }

    fn read_device_config(&self, offset: u64) -> u32 {
        log!("read_device_config {}", offset);
        let result = match offset {
            0 => self.sector_count() & ((1 << 32) - 1),
            4 => self.sector_count() >> 32,
            _ => 0
        };
        result as u32
    }
}
