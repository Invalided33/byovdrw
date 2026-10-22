# byovdrw

Kernel call gate via BYOVD + SSDT PTE remapping. Hijacks a single SSDT entry (`NtCreateTransaction`) by swapping the underlying page table entry to point to a usermode-controlled data page. After bootstrap, arbitrary kernel functions can be called from usermode via a plain `syscall` instruction — no driver loaded, no ROP chains, no threads.

**Patch-on-demand**: the SSDT slot is only modified during the ~2μs syscall dispatch window. Between calls, the slot holds its original ntoskrnl value. Any SSDT scanner polling between calls sees a clean table.

## How it works

```
┌─────────────────────────────────────────────────────────────┐
│  Bootstrap (one-time, ~2 seconds)                           │
│                                                             │
│  1. Load embedded BYOVD driver (AmdTools64)                 │
│  2. Superfetch VA→PA translation for all kernel addresses   │
│  3. Find SSDT, gadgets, CR3 via PE scan + phys read         │
│  4. KForge v1 (ROP) to get PML4E kernel VA                  │
│  5. Walk page tables: PML4E → PDPTE → PDE → PTE             │
│  6. Allocate locked usermode page, copy SSDT page content   │
│  7. Fix PFN refcounts (MmPfnDatabase)                       │
│  8. Swap PTE (or split 2MB PDE → 4KB) via KForge v1 write   │
│  9. Flush TLB, unload driver, delete files from disk        │
│                                                             │
│  Result: kernel SSDT page now backed by our data page       │
├─────────────────────────────────────────────────────────────┤
│  Runtime (per call, ~2μs)                                   │
│                                                             │
│  1. Write patched SSDT entry (volatile)                     │
│  2. syscall NtCreateTransaction → kernel dispatches to func │
│  3. Restore original SSDT entry (volatile)                  │
│                                                             │
│  No driver, no ROP, no extra threads                        │
└─────────────────────────────────────────────────────────────┘
```

## Compatibility

Works on all Windows 10/11 x64 builds:

| Build range | Retpoline | SSDT discovery | MmPfnDatabase |
|---|---|---|---|
| Win10 1507–1803 | Synthetic (shellcode stub) | Section-walk | Live kernel scan |
| Win10 1809–22H2 | Native (`_guard_retpoline_exit_indirect_rax`) | Section-walk | Live kernel scan |
| Win11 21H2–26H1 | Native | Section-walk | Live kernel scan |

Key compatibility fixes:
- **Retpoline**: pre-Spectre kernels (< 1809) don't have the `_guard_retpoline_exit_indirect_rax` gadget. A 32-byte synthetic retpoline is written to an executable user page as fallback.
- **SSDT discovery**: walks PE section table instead of OptionalHeader range. The old approach used `SizeOfUninitializedData` which is wrong on Win10 2004+ and all Win11.
- **MmPfnDatabase**: not exported on Win11 24H2+. Extracted by reading the live `MmGetVirtualForPhysical` body from kernel memory and scanning for `mov rax, imm64`.

## Building

```
cargo build --release
```

Requires:
- Rust nightly (edition 2024, inline asm)
- Windows x64 target
- The `res/` directory with AmdTools64.sys, amdtools.inf, Amdtools.cat (embedded at compile time via `include_bytes!`)

## Running

Must run as Administrator:

```
.\target\release\byovdrw.exe
```

The driver is extracted to a temp directory with random names, installed via SetupAPI, then all files are deleted from disk immediately after the kernel loads the .sys. On exit (press Enter), the original PTE/PDE is restored.

## Project structure

```
src/
├── main.rs       # Bootstrap, PTE manipulation, KCall patch-on-demand, cleanup
├── driver.rs     # Embedded driver: extract, install, open, wipe, uninstall
├── export.rs     # ntoskrnl PE scan: ROP gadgets, ZwTerminateThread, export resolver
└── ssdt.rs       # KeServiceDescriptorTable discovery via KiSystemCall64 signature
res/
├── AmdTools64.sys  # BYOVD driver (embedded in binary)
├── amdtools.inf    # INF template (patched with random filenames at runtime)
└── Amdtools.cat    # Catalog file
```

## References

Built studying and referencing:
- [malk](https://github.com/figueiredo-lucas/malk) — C++ BYOVD kernel manipulation toolkit
- [KernelForge (kforge)](https://github.com/figueiredo-lucas/kforge) — Rust SSDT hijack with anti-cheat protections, ROP pooling, runtime encryption

## Disclaimer

This is a research project for educational purposes. The techniques demonstrated here interact with kernel memory and can cause system instability (BSOD) if misused. Use at your own risk on systems you own.
