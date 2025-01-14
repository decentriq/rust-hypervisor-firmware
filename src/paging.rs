use x86_64::{
    registers::control::Cr3,
    structures::paging::{PageSize, PageTable, PageTableFlags, PhysFrame, Size2MiB},
    PhysAddr,
};

// Amount of memory we identity map in setup(), max 512 GiB.
const ADDRESS_SPACE_GIB: usize = 4;
const TABLE: PageTable = PageTable::new();

// Put the Page Tables in static muts to make linking easier
#[no_mangle]
static mut L4_TABLE: PageTable = PageTable::new();
#[no_mangle]
static mut L3_TABLE: PageTable = PageTable::new();
#[no_mangle]
static mut L2_TABLES: [PageTable; ADDRESS_SPACE_GIB] = [TABLE; ADDRESS_SPACE_GIB];

pub fn mark_read_only(range: &[u8]) {
    let start_ptr = range.as_ptr();

    // Sanity check the address
    assert_eq!(start_ptr.align_offset(1 << 21), 0);
    let l3 = unsafe { &mut L3_TABLE };

    let mut current_page_addr = PhysAddr::new(start_ptr as u64);
    while current_page_addr.as_u64() < (start_ptr as u64) + range.len() as u64 {
        let l2_offset = (current_page_addr.as_u64() >> 21) & ((1 << 9) - 1);
        let l3_offset = (current_page_addr.as_u64() >> 21 >> 9) & ((1 << 9) - 1);
        let l4_offset = (current_page_addr.as_u64() >> 21 >> 9 >> 9) & ((1 << 9) - 1);

        log!("ptr: {:p}, l4: {:x}, l3: {:x}, l2: {:x}", current_page_addr, l4_offset, l3_offset, l2_offset);
        assert_eq!(l4_offset, 0);
        let l2_table_addr: PhysAddr = l3[l3_offset as usize].addr();
        let l2_table = unsafe { &mut *(l2_table_addr.as_u64() as *mut PageTable) };
        unsafe { log!("l2 addr: {:p}, L2_TABLES addr: {:p}", l2_table, &L2_TABLES); }
        let entry = &mut l2_table[l2_offset as usize];
        entry.set_flags(entry.flags() & !PageTableFlags::WRITABLE);
        // entry.set_flags();
        current_page_addr += Size2MiB::SIZE;
    }

    unsafe {
        x86_64::registers::control::Cr0::update(|cr0| {
            *cr0 = *cr0 | x86_64::registers::control::Cr0Flags::WRITE_PROTECT;
        });
    }
}

pub fn setup() {
    // SAFETY: This function is idempotent and only writes to static memory and
    // CR3. Thus, it is safe to run multiple times or on multiple threads.
    let (l4, l3, l2s) = unsafe { (&mut L4_TABLE, &mut L3_TABLE, &mut L2_TABLES) };
    log!("Setting up {} GiB identity mapping", ADDRESS_SPACE_GIB);
    let pt_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // Setup Identity map using L2 huge pages
    let mut next_addr = PhysAddr::new(0);
    for l2 in l2s.iter_mut() {
        for l2e in l2.iter_mut() {
            l2e.set_addr(next_addr, pt_flags | PageTableFlags::HUGE_PAGE);
            next_addr += Size2MiB::SIZE;
        }
    }

    // Point L3 at L2s
    for (i, l2) in l2s.iter().enumerate() {
        l3[i].set_addr(phys_addr(l2), pt_flags);
    }

    // Point L4 at L3
    l4[0].set_addr(phys_addr(l3), pt_flags);

    // Point Cr3 at L4
    let (cr3_frame, cr3_flags) = Cr3::read();
    let l4_frame = PhysFrame::from_start_address(phys_addr(l4)).unwrap();
    if cr3_frame != l4_frame {
        unsafe { Cr3::write(l4_frame, cr3_flags) };
    }
    log!("Page tables setup");
}

// Map a virtual address to a PhysAddr (assumes identity mapping)
fn phys_addr<T>(virt_addr: *const T) -> PhysAddr {
    PhysAddr::new(virt_addr as u64)
}
