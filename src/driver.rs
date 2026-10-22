//! Embedded driver — extract with random names, install, open, wipe files immediately.
//!
//! Flow: generate random dir+filenames → write .sys/.inf/.cat → install PnP device →
//! open handle → DELETE all files from disk (kernel already loaded .sys into memory) →
//! on cleanup: close handle → remove PnP device node → delete empty dir.

use std::path::PathBuf;
use std::{fs, mem, ptr};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

type HANDLE = *mut std::ffi::c_void;

static DRV_SYS: &[u8] = include_bytes!("../res/AmdTools64.sys");
static DRV_INF_TEMPLATE: &str = include_str!("../res/amdtools.inf");
static DRV_CAT: &[u8] = include_bytes!("../res/Amdtools.cat");

const IFACE_GUID: windows_sys::core::GUID = windows_sys::core::GUID {
    data1: 0x1232175B,
    data2: 0x1C34,
    data3: 0x41FD,
    data4: [0xB1, 0x01, 0x34, 0x2D, 0x47, 0xB8, 0x28, 0xAC],
};

/// Generate a random alphanumeric string using rdtsc as entropy.
fn rand_name(len: usize) -> String {
    let mut seed: u64;
    unsafe {
        core::arch::asm!("rdtsc", out("eax") seed, out("edx") _);
    }
    seed ^= std::process::id() as u64;
    let charset = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut name = String::with_capacity(len);
    for i in 0..len {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((seed >> 33) as usize ^ i) % charset.len();
        name.push(charset[idx] as char);
    }
    name
}

pub struct EmbeddedDriver {
    pub handle: HANDLE,
    temp_dir: PathBuf,
    installed: bool,
}

impl EmbeddedDriver {
    pub fn load() -> Result<Self, String> {
        // Already installed from a previous run? Just open.
        if let Ok(h) = open_device() {
            return Ok(Self {
                handle: h,
                temp_dir: PathBuf::new(),
                installed: false,
            });
        }

        // Random directory name inside %TEMP%
        let dir_name = rand_name(12);
        let temp_dir = std::env::temp_dir().join(&dir_name);
        fs::create_dir_all(&temp_dir).map_err(|e| format!("mkdir: {}", e))?;

        // Random file names (keep extensions — SetupAPI needs them)
        let sys_name = format!("{}.sys", rand_name(8));
        let inf_name = format!("{}.inf", rand_name(8));
        let cat_name = format!("{}.cat", rand_name(8));

        let sys_path = temp_dir.join(&sys_name);
        let inf_path = temp_dir.join(&inf_name);
        let cat_path = temp_dir.join(&cat_name);

        // Patch the INF to reference our random .sys and .cat filenames.
        // Original INF references "amdtools64.sys" and "AmdTools.cat".
        let inf_content = DRV_INF_TEMPLATE
            .replace("amdtools64.sys", &sys_name)
            .replace("AmdTools64.sys", &sys_name)
            .replace("AmdTools.cat", &cat_name);

        fs::write(&sys_path, DRV_SYS).map_err(|e| format!("write sys: {}", e))?;
        fs::write(&inf_path, inf_content.as_bytes()).map_err(|e| format!("write inf: {}", e))?;
        fs::write(&cat_path, DRV_CAT).map_err(|e| format!("write cat: {}", e))?;

        // Install
        let installed = install_driver(&inf_path)?;

        // Open handle
        let handle = open_device()?;

        // Driver is loaded into kernel memory — wipe files from disk immediately.
        // The .sys is already mapped by the kernel, disk copy is not needed.
        let _ = fs::remove_file(&sys_path);
        let _ = fs::remove_file(&inf_path);
        let _ = fs::remove_file(&cat_path);
        let _ = fs::remove_dir(&temp_dir); // succeeds if empty

        Ok(Self {
            handle,
            temp_dir,
            installed,
        })
    }

    pub fn unload(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = ptr::null_mut();
        }
        if self.installed {
            let _ = uninstall_driver();
            self.installed = false;
        }
        // Belt-and-suspenders cleanup of temp dir (may already be gone)
        let _ = fs::remove_dir_all(&self.temp_dir);
    }
}

impl Drop for EmbeddedDriver {
    fn drop(&mut self) {
        self.unload();
    }
}

// ── SetupAPI install/uninstall ──────────────────────────────────────

fn install_driver(inf_path: &std::path::Path) -> Result<bool, String> {
    let inf_w: Vec<u16> = inf_path
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let hwid_w: Vec<u16> = "*AMDTOOLSDEV\0\0".encode_utf16().chain(Some(0)).collect();

    let mut need_reboot: i32 = 0;
    let ok = unsafe {
        UpdateDriverForPlugAndPlayDevicesW(
            ptr::null_mut(),
            hwid_w.as_ptr(),
            inf_w.as_ptr(),
            0x01,
            &mut need_reboot,
        )
    };
    if ok != 0 {
        return Ok(true);
    }

    let err = unsafe { GetLastError() };
    if err == ERROR_NO_SUCH_DEVINST {
        create_devnode_and_install(inf_path)?;
        return Ok(true);
    }
    Err(format!("UpdateDriver failed: err={}", err))
}

fn create_devnode_and_install(inf_path: &std::path::Path) -> Result<(), String> {
    let inf_w: Vec<u16> = inf_path
        .to_string_lossy()
        .encode_utf16()
        .chain(Some(0))
        .collect();

    let class_name_buf = &mut [0u16; 256];
    let mut class_guid: windows_sys::core::GUID = unsafe { mem::zeroed() };
    if unsafe {
        SetupDiGetINFClassW(
            inf_w.as_ptr(),
            &mut class_guid,
            class_name_buf.as_mut_ptr(),
            class_name_buf.len() as u32,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(format!("SetupDiGetINFClassW: {}", unsafe {
            GetLastError()
        }));
    }

    let di = unsafe { SetupDiCreateDeviceInfoList(&class_guid, ptr::null_mut()) };
    if di == -1isize {
        return Err("CreateDeviceInfoList failed".into());
    }

    let mut did: SP_DEVINFO_DATA = unsafe { mem::zeroed() };
    did.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;

    let class_w: Vec<u16> = "System\0".encode_utf16().collect();
    if unsafe {
        SetupDiCreateDeviceInfoW(
            di,
            class_w.as_ptr(),
            &class_guid,
            ptr::null(),
            ptr::null_mut(),
            0x01,
            &mut did,
        )
    } == 0
    {
        let e = unsafe { GetLastError() };
        unsafe {
            SetupDiDestroyDeviceInfoList(di);
        }
        return Err(format!("CreateDeviceInfoW: {}", e));
    }

    let hwid_w: Vec<u16> = "*AMDTOOLSDEV\0\0".encode_utf16().collect();
    if unsafe {
        SetupDiSetDeviceRegistryPropertyW(
            di,
            &mut did,
            0x01,
            hwid_w.as_ptr() as *const u8,
            (hwid_w.len() * 2) as u32,
        )
    } == 0
    {
        let e = unsafe { GetLastError() };
        unsafe {
            SetupDiDestroyDeviceInfoList(di);
        }
        return Err(format!("SetRegistryProperty: {}", e));
    }

    if unsafe { SetupDiCallClassInstaller(0x19, di, &mut did) } == 0 {
        let e = unsafe { GetLastError() };
        unsafe {
            SetupDiDestroyDeviceInfoList(di);
        }
        return Err(format!("CallClassInstaller(REGISTER): {}", e));
    }
    unsafe {
        SetupDiDestroyDeviceInfoList(di);
    }

    let mut need_reboot: i32 = 0;
    let hwid_up: Vec<u16> = "*AMDTOOLSDEV\0".encode_utf16().chain(Some(0)).collect();
    if unsafe {
        UpdateDriverForPlugAndPlayDevicesW(
            ptr::null_mut(),
            hwid_up.as_ptr(),
            inf_w.as_ptr(),
            0x01,
            &mut need_reboot,
        )
    } == 0
    {
        return Err(format!("UpdateDriver: {}", unsafe { GetLastError() }));
    }
    Ok(())
}

fn open_device() -> Result<HANDLE, String> {
    for i in 0..5 {
        let p = format!(
            "\\\\?\\ROOT#SYSTEM#{:04}#{{1232175b-1c34-41fd-b101-342d47b828ac}}",
            i
        );
        let wp: Vec<u16> = p.encode_utf16().chain(Some(0)).collect();
        let h = unsafe {
            CreateFileW(
                wp.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return Ok(h);
        }
    }
    unsafe {
        let di = SetupDiGetClassDevsW(
            &IFACE_GUID,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        );
        if di == -1isize {
            return Err("no device".into());
        }
        let mut id: SP_DEVICE_INTERFACE_DATA = mem::zeroed();
        id.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        if SetupDiEnumDeviceInterfaces(di, ptr::null(), &IFACE_GUID, 0, &mut id) == 0 {
            SetupDiDestroyDeviceInfoList(di);
            return Err("no interface".into());
        }
        let mut sz = 0u32;
        SetupDiGetDeviceInterfaceDetailW(di, &id, ptr::null_mut(), 0, &mut sz, ptr::null_mut());
        let mut buf = vec![0u8; sz as usize];
        let det = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        (*det).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        if SetupDiGetDeviceInterfaceDetailW(di, &id, det, sz, ptr::null_mut(), ptr::null_mut()) == 0
        {
            SetupDiDestroyDeviceInfoList(di);
            return Err("detail failed".into());
        }
        let h = CreateFileW(
            &(*det).DevicePath as *const u16,
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );
        SetupDiDestroyDeviceInfoList(di);
        if h != INVALID_HANDLE_VALUE {
            Ok(h)
        } else {
            Err("open failed".into())
        }
    }
}

fn uninstall_driver() -> Result<(), String> {
    unsafe {
        let di = SetupDiGetClassDevsW(
            &IFACE_GUID,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_DEVICEINTERFACE | DIGCF_PRESENT,
        );
        if di == -1isize {
            return Ok(());
        }
        let mut id: SP_DEVICE_INTERFACE_DATA = mem::zeroed();
        id.cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32;
        if SetupDiEnumDeviceInterfaces(di, ptr::null(), &IFACE_GUID, 0, &mut id) == 0 {
            SetupDiDestroyDeviceInfoList(di);
            return Ok(());
        }
        let mut did: SP_DEVINFO_DATA = mem::zeroed();
        did.cbSize = mem::size_of::<SP_DEVINFO_DATA>() as u32;
        let mut sz = 0u32;
        SetupDiGetDeviceInterfaceDetailW(di, &id, ptr::null_mut(), 0, &mut sz, ptr::null_mut());
        let mut buf = vec![0u8; sz as usize];
        let det = buf.as_mut_ptr() as *mut SP_DEVICE_INTERFACE_DETAIL_DATA_W;
        (*det).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
        SetupDiGetDeviceInterfaceDetailW(di, &id, det, sz, ptr::null_mut(), &mut did);
        SetupDiCallClassInstaller(0x05, di, &mut did); // DIF_REMOVE
        SetupDiDestroyDeviceInfoList(di);
        Ok(())
    }
}
