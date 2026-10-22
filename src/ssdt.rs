//! SSDT discovery — find KeServiceDescriptorTable by scanning ntoskrnl PE.
//!
//! Walks executable, non-discardable sections (not OptionalHeader range)
//! to find KiSystemCall64.  The old approach used `SizeOfUninitializedData`
//! from the optional header which is wrong on Win10 2004+ and all Win11 —
//! it starts AFTER KiSystemCall64, causing the sig to never be found.

/// Find KeServiceDescriptorTable VA by scanning ntoskrnl PE on disk.
/// Looks for KiSystemCall64 (second swapgs pattern) then `lea r10, [rip+imm32]`.
pub fn find_ke_service_descriptor_table(kbase: u64, kname: &str) -> Option<u64> {
    let data = std::fs::read(format!("C:\\Windows\\System32\\{}", kname)).ok()?;
    if data.len() < 0x200 {
        return None;
    }

    let lfa = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if u32::from_le_bytes(data[lfa..lfa + 4].try_into().ok()?) != 0x4550 {
        return None;
    }

    // KiSystemCall64 signature:
    //   swapgs; mov gs:[0x10], rsp; mov rsp, gs:[0x1A8]
    let sig: [u8; 21] = [
        0x0F, 0x01, 0xF8, 0x65, 0x48, 0x89, 0x24, 0x25, 0x10, 0x00, 0x00, 0x00, 0x65, 0x48, 0x8B,
        0x24, 0x25, 0xA8, 0x01, 0x00, 0x00,
    ];

    // Walk executable, non-discardable sections and collect every sig match.
    // First match = KiSystemCall32, second = KiSystemCall64 (our target).
    let mut matches: Vec<usize> = Vec::new();
    walk_exec_sections(&data, lfa, |raw_off, raw_sz| {
        let end = (raw_off + raw_sz).min(data.len());
        if end < raw_off + sig.len() {
            return;
        }
        let mut i = raw_off;
        while i + sig.len() <= end {
            if data[i..i + sig.len()] == sig {
                matches.push(i);
                i += sig.len();
            } else {
                i += 1;
            }
        }
    });

    if matches.len() < 2 {
        println!(
            "  [ssdt] KiSystemCall64 not found ({} matches)",
            matches.len()
        );
        return None;
    }
    let ki_syscall64_off = matches[1];
    println!(
        "  [ssdt] KiSystemCall64 file offset = 0x{:X}",
        ki_syscall64_off
    );

    // Scan forward for `lea r10, [rip+imm32]` (4C 8D 15 XX XX XX XX)
    for i in ki_syscall64_off..ki_syscall64_off + 0x600 {
        if i + 7 > data.len() {
            break;
        }
        if data[i] == 0x4C && data[i + 1] == 0x8D && data[i + 2] == 0x15 {
            let imm = i32::from_le_bytes(data[i + 3..i + 7].try_into().ok()?);
            let rva = file_offset_to_rva(&data, lfa, i)?;
            let sdt_va = kbase + rva + 7 + imm as u64;
            println!("  [ssdt] KeServiceDescriptorTable VA = 0x{:X}", sdt_va);
            return Some(sdt_va);
        }
    }

    println!("  [ssdt] lea r10 not found after KiSystemCall64");
    None
}

/// Invoke `visit(raw_off, raw_size)` for every executable, non-discardable
/// section in the PE.
fn walk_exec_sections(data: &[u8], lfa: usize, mut visit: impl FnMut(usize, usize)) {
    let coff = lfa + 4;
    let Ok(ns_bytes) = data[coff + 2..coff + 4].try_into() else {
        return;
    };
    let Ok(oh_bytes) = data[coff + 16..coff + 18].try_into() else {
        return;
    };
    let nsec = u16::from_le_bytes(ns_bytes) as usize;
    let ohsz = u16::from_le_bytes(oh_bytes) as usize;
    let sh0 = coff + 20 + ohsz;
    for i in 0..nsec {
        let sh = sh0 + i * 40;
        if sh + 40 > data.len() {
            break;
        }
        let Ok(ch_bytes) = data[sh + 36..sh + 40].try_into() else {
            continue;
        };
        let ch = u32::from_le_bytes(ch_bytes);
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000, IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
        if (ch & 0x2000_0000) == 0 || (ch & 0x0200_0000) != 0 {
            continue;
        }
        let raw_off =
            u32::from_le_bytes(data[sh + 20..sh + 24].try_into().unwrap_or_default()) as usize;
        let raw_sz =
            u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap_or_default()) as usize;
        let virt_sz =
            u32::from_le_bytes(data[sh + 8..sh + 12].try_into().unwrap_or_default()) as usize;
        visit(raw_off, raw_sz.min(virt_sz));
    }
}

fn file_offset_to_rva(data: &[u8], lfa: usize, foff: usize) -> Option<u64> {
    let coff = lfa + 4;
    let nsec = u16::from_le_bytes(data[coff + 2..coff + 4].try_into().ok()?) as usize;
    let ohsz = u16::from_le_bytes(data[coff + 16..coff + 18].try_into().ok()?) as usize;
    let sh0 = coff + 20 + ohsz;
    for i in 0..nsec {
        let sh = sh0 + i * 40;
        if sh + 40 > data.len() {
            break;
        }
        let raw_off = u32::from_le_bytes(data[sh + 20..sh + 24].try_into().ok()?) as usize;
        let raw_sz = u32::from_le_bytes(data[sh + 16..sh + 20].try_into().ok()?) as usize;
        let vrva = u32::from_le_bytes(data[sh + 12..sh + 16].try_into().ok()?) as usize;
        if foff >= raw_off && foff < raw_off + raw_sz {
            return Some((foff - raw_off + vrva) as u64);
        }
    }
    None
}
