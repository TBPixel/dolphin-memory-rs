// dolphin-memory provides an API for hooking into dolphin and accessing runtime memory. It conveniently
// handles mapping of common data types, endian-ness, pointer chains and more. Accessing memory
// in this way is implicitly unsafe, but an effort is being made to ensure the API is as safe
// as it can be for use.

use std::ffi;
use std::io;
use std::mem;
use std::num::TryFromIntError;
use std::ptr;

use byteorder::{BigEndian, ReadBytesExt};
use process_memory::{
    CopyAddress, ProcessHandle, ProcessHandleExt, PutAddress, TryIntoProcessHandle,
};
use thiserror::Error;
use winapi::um::memoryapi;
use winapi::um::psapi;
use winapi::um::winnt;

// MEM1_STRIP_START is  useful for stripping the `8` from the start
// of memory addresses within the MEM1 region.
pub const MEM1_STRIP_START: usize = 0x3FFFFFFF;

pub const MEM1_START: usize = 0x10000000;
pub const MEM1_END: usize = 0x81800000;
pub const MEM1_SIZE: usize = 0x2000000;
pub const MEM2_SIZE: usize = 0x4000000;

fn error_chain_fmt(
    e: &impl std::error::Error,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    writeln!(f, "{}\n", e)?;
    let mut current = e.source();
    while let Some(cause) = current {
        writeln!(f, "Caused by:\n\t{}", cause)?;
        current = cause.source();
    }
    Ok(())
}

#[derive(Error)]
pub enum ProcessError {
    #[error("failed to find process for dolphin")]
    DolphinNotFound,
    #[error("emulation not running")]
    EmulationNotRunning,
    #[error("unknown error")]
    UnknownError(#[source] io::Error),
}

impl std::fmt::Debug for ProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        error_chain_fmt(self, f)
    }
}

#[derive(Debug, Clone)]
pub struct Process {
    pid: u32,
    handle: winnt::HANDLE,
}

#[derive(Clone, Debug)]
pub struct EmuRAMAddresses {
    mem_1: usize,
    mem_2: usize,
}

#[derive(Debug, Clone)]
pub struct Dolphin {
    handle: ProcessHandle,
    ram: EmuRAMAddresses,
}

// this is to allow the std::ffi::c_void pointer of the
// process_memory::ProcessHandle to be passed through threads.
// This is technically unsafe, but in practice it _shouldn't_ cause
// issues as we're never changing anything about this pointer.
unsafe impl Send for Dolphin {}

impl Dolphin {
    // new hooks into the Dolphin process and into the gamecube ram. This can block while looking,
    // but more likely it will error on failure. An easy pattern to check this on repeat is to loop and break
    // on success. You can opt-to do something with the error if you choose, but during hook it's really only basic insights.
    pub fn new() -> Result<Self, ProcessError> {
        let handle = match get_pid(vec!["Dolphin.exe", "DolphinQt1.exe", "DolphinWx.exe"]) {
            Some(h) => h
                .try_into_process_handle()
                .map_err(|e| ProcessError::UnknownError(e))?,
            None => return Err(ProcessError::DolphinNotFound),
        };

        let ram = ram_info(handle)?;
        let handle = handle.set_arch(process_memory::Architecture::Arch32Bit);

        Ok(Dolphin { handle, ram })
    }

    // is_emulation_running queries ram info to determine if the emulator is still running.
    pub fn is_emulation_running(&self) -> bool {
        match ram_info(self.handle) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    // read takes a size, starting address and an optional list of pointer offsets,
    // following those addresses until it hits the underyling data.
    //
    // TODO: There's a number of issues with this function. For starters,
    // it only knows how to handle MEM1 addresses. Supporting addresses
    // in the MEM2 space will require some refactoring, but I believe it can
    // be done while maintaining this API.
    // Additionally, this code will have to resolve the addresses given to it
    // every single time it's run, but in all likelihood the addresses will not
    // change that frequently. It would be a good idea to introduce a cache layer here
    // which caches the output address using a hash of the input address + offsets.
    pub fn read(
        &self,
        size: usize,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<Vec<u8>> {
        // TODO: this should realistically be able to handle picking mem_1 or mem_2,
        // but we'll just stick to mem_1 for now.
        let starting_address = starting_address & MEM1_STRIP_START;
        let mut buffer = vec![0_u8; size];

        if let Some(offsets) = pointer_offsets {
            let addr = self.resolve_pointer_address(starting_address, offsets)?;
            self.handle.copy_address(addr, &mut buffer)?;

            return Ok(buffer);
        }

        let address = self
            .handle
            .get_offset(&[self.ram.mem_1 + starting_address])?;

        self.handle.copy_address(address, &mut buffer)?;

        Ok(buffer)
    }

    // write a buffer of bytes to the given address or pointer of address.
    pub fn write(
        &self,
        buf: &[u8],
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        if let Some(offsets) = pointer_offsets {
            let addr = self.resolve_pointer_address(starting_address, offsets)?;
            self.handle.put_address(addr, buf)?;

            return Ok(());
        }

        let starting_address = self.ram.mem_1 + (starting_address & MEM1_STRIP_START);
        self.handle.put_address(starting_address, buf)?;

        Ok(())
    }

    // write_u8 wraps write and provides a simple interface for writing a u8 to dolphin memory
    pub fn write_u8(
        &self,
        n: u8,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&[n], starting_address, pointer_offsets)
    }

    // write_u16 wraps write and provides a simple interface for writing a u16 to dolphin memory
    pub fn write_u16(
        &self,
        n: u16,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&n.to_be_bytes(), starting_address, pointer_offsets)
    }

    // write_u32 wraps write and provides a simple interface for writing a u32 to dolphin memory
    pub fn write_u32(
        &self,
        n: u32,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&n.to_be_bytes(), starting_address, pointer_offsets)
    }

    // write_i8 wraps write and provides a simple interface for writing a i8 to dolphin memory
    pub fn write_i8(
        &self,
        n: i8,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&n.to_be_bytes(), starting_address, pointer_offsets)
    }

    // write_i16 wraps write and provides a simple interface for writing a i16 to dolphin memory
    pub fn write_i16(
        &self,
        n: i16,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&n.to_be_bytes(), starting_address, pointer_offsets)
    }

    // write_i32 wraps write and provides a simple interface for writing a i32 to dolphin memory
    pub fn write_i32(
        &self,
        n: i32,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&n.to_be_bytes(), starting_address, pointer_offsets)
    }

    // write_f32 wraps write and provides a simple interface for writing an f32 to dolphin memory
    pub fn write_f32(
        &self,
        f: f32,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<()> {
        self.write(&f.to_be_bytes(), starting_address, pointer_offsets)
    }

    // read_u8 wraps read to provide a convenient cast to an u8.
    pub fn read_u8(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<u8> {
        let buf = self.read(mem::size_of::<u8>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_u8()?;

        Ok(n)
    }

    // read_u16 wraps read to provide a convenient cast to an u16.
    pub fn read_u16(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<u16> {
        let buf = self.read(mem::size_of::<u16>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_u16::<BigEndian>()?;

        Ok(n)
    }

    // read_u32 wraps read to provide a convenient cast to an u32.
    pub fn read_u32(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<u32> {
        let buf = self.read(mem::size_of::<u32>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_u32::<BigEndian>()?;

        Ok(n)
    }

    // read_i8 wraps read to provide a convenient cast to an i8.
    pub fn read_i8(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<i8> {
        let buf = self.read(mem::size_of::<i8>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_i8()?;

        Ok(n)
    }

    // read_i16 wraps read to provide a convenient cast to an i16.
    pub fn read_i16(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<i16> {
        let buf = self.read(mem::size_of::<i16>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_i16::<BigEndian>()?;

        Ok(n)
    }

    // read_i32 wraps read to provide a convenient cast to an i32.
    pub fn read_i32(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<i32> {
        let buf = self.read(mem::size_of::<i32>(), starting_address, pointer_offsets)?;
        let n = std::io::Cursor::new(buf).read_i32::<BigEndian>()?;

        Ok(n)
    }

    // read_f32 wraps read to provide a convenient cast to an f32.
    pub fn read_f32(
        &self,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<f32> {
        let buf = self.read(mem::size_of::<f32>(), starting_address, pointer_offsets)?;
        let f = std::io::Cursor::new(buf).read_f32::<BigEndian>()?;

        Ok(f)
    }

    // read_string provides a convenient read and cast to a String.
    // Note that strings are expected to be utf8 and the length will account
    // for the number of bytes to read.
    pub fn read_string(
        &self,
        length: usize,
        starting_address: usize,
        pointer_offsets: Option<&[usize]>,
    ) -> io::Result<String> {
        let buf = self.read(length, starting_address, pointer_offsets)?;
        let string = String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(string)
    }

    // resolve_pointer_address follows a series of pointer offsets until
    // it reachines the last pointer, in which case that address is returned.
    //
    // note that it is returned as a fully-qualified address, meaning no memory
    // offsets are needed.
    fn resolve_pointer_address(
        &self,
        starting_address: usize,
        offsets: &[usize],
    ) -> io::Result<usize> {
        // TODO: this should realistically be able to handle picking mem_1 or mem_2,
        // but we'll just stick to mem_1 for now.
        let starting_address = starting_address & MEM1_STRIP_START;

        // read the starting address to get the initial pointer.
        // we could have multiple pointer chains to follow, but we know the starting
        // address is where we want to look first to kick ourselves off on the right foot.
        let mut ptr_buffer = vec![0_u8; std::mem::size_of::<u32>()];
        self.handle
            .copy_address(self.ram.mem_1 + starting_address, &mut ptr_buffer)?;

        let mut current_ptr: usize = io::Cursor::new(ptr_buffer)
            .read_u32::<BigEndian>()?
            .try_into()
            .map_err(|e: TryFromIntError| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if current_ptr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null pointer address",
            ));
        }

        let mut ptr_addr: usize = 0;
        for (index, offset) in offsets.iter().enumerate() {
            // We'll need a new ptr_buffer for each pointer
            let mut ptr_buffer = vec![0_u8; std::mem::size_of::<u32>()];

            // Copy and update the current address for each iteration,
            // as this will be our starting point on subsequent loops.
            // This also conveniently handles dropping the `8` a the start
            // of all MEM1 addresses.
            // TODO: Update this to better handle MEM2.
            let addr = (current_ptr & MEM1_STRIP_START) + offset;

            // the last iteration we've likely reached the value we're looking
            // for, so lets just copy that and break out.
            if index == offsets.len() - 1 {
                if current_ptr == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "null pointer address",
                    ));
                }

                ptr_addr = self.ram.mem_1 + addr;
                break;
            }

            self.handle
                .copy_address(self.ram.mem_1 + addr, &mut ptr_buffer)?;
            current_ptr = io::Cursor::new(ptr_buffer)
                .read_u32::<BigEndian>()?
                .try_into()
                .map_err(|e: TryFromIntError| {
                    io::Error::new(io::ErrorKind::Other, e.to_string())
                })?;

            if current_ptr == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "null pointer address",
                ));
            }
        }

        if ptr_addr == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "null pointer address",
            ));
        }

        Ok(ptr_addr)
    }
}

// get_pid looks up the process id for the given list of process names
fn get_pid(process_names: Vec<&str>) -> Option<process_memory::Pid> {
    fn utf8_to_string(bytes: &[i8]) -> String {
        use std::ffi::CStr;
        unsafe {
            CStr::from_ptr(bytes.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    }

    let mut entry = winapi::um::tlhelp32::PROCESSENTRY32 {
        dwSize: std::mem::size_of::<winapi::um::tlhelp32::PROCESSENTRY32>() as u32,
        szExeFile: [0; winapi::shared::minwindef::MAX_PATH],
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
    };

    let snapshot: winapi::um::winnt::HANDLE;
    snapshot = unsafe {
        winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPPROCESS, 0)
    };

    if unsafe { winapi::um::tlhelp32::Process32First(snapshot, &mut entry) }
        == winapi::shared::minwindef::TRUE
    {
        while unsafe { winapi::um::tlhelp32::Process32Next(snapshot, &mut entry) }
            == winapi::shared::minwindef::TRUE
        {
            if process_names.contains(&utf8_to_string(&entry.szExeFile).as_str()) {
                return Some(entry.th32ProcessID);
            }
        }
    }

    None
}

// ram_info is a convenient function wrapper for querying the emulated GC heap addresses.
fn ram_info(process: ProcessHandle) -> Result<EmuRAMAddresses, ProcessError> {
    let mut mem1: Option<usize> = None;
    let mut mem2: Option<usize> = None;

    let mut p = ptr::null_mut();
    let mut info = winnt::MEMORY_BASIC_INFORMATION::default();
    loop {
        // Attempt to retrieve a range of pages within the virtual address space
        let size = unsafe {
            memoryapi::VirtualQueryEx(
                process.0,
                p,
                &mut info,
                mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
            )
        };
        if size != mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>() {
            break;
        }

        // check region size so that we know it's mem2
        if info.RegionSize == MEM2_SIZE {
            let region_base_address = info.BaseAddress as usize;

            if let Some(region) = mem1 {
                if region_base_address > region + MEM1_START {
                    // in some cases MEM2 could actually be before MEM1. Once we find
                    // MEM1, ignore regions of this size that are too far away. There
                    // apparently are other non-MEM2 regions of size 0x40000000.
                    break;
                }
            }

            // View the comment for MEM1
            let mut ws_info = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                VirtualAddress: info.BaseAddress,
                ..Default::default()
            };
            let page_info = {
                match unsafe { psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                        .try_into()
                        .unwrap(),
                ) }{
                    0 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            };
            if page_info.is_ok() && ws_info.VirtualAttributes.Valid() == 1 {
                // note that mem::transmute_copy triggers undefined behavior
                // if the output type is larger than the pointer.
                //
                // A good safety precaution here would be to check this before
                // calling mem::transmute_copy, just to be safe.
                unsafe {
                    mem2 = Some(mem::transmute_copy(&info.BaseAddress));
                }
            }
        } else if mem1.is_none() && info.RegionSize == MEM1_SIZE && info.Type == winnt::MEM_MAPPED {
            // Here it's likely the right page, but it can happen that multiple pages
            // with these criteria exists and have nothing to do with emulated memory.
            // Only the right page has valid working set information so an additional
            // check is required that it is backed by physical memory.
            let mut ws_info = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                VirtualAddress: info.BaseAddress,
                ..Default::default()
            };
            let page_info = {
                match unsafe { psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                        .try_into()
                        .unwrap(),
                ) }{
                    0 => Err(io::Error::last_os_error()),
                    _ => Ok(()),
                }
            };
            if page_info.is_ok() && ws_info.VirtualAttributes.Valid() == 1 {
                // note that mem::transmute_copy triggers undefined behavior
                // if the output type is larger than the pointer.
                //
                // A good safety precaution here would be to check this before
                // calling mem::transmute_copy, just to be safe.
                unsafe {
                    mem1 = Some(mem::transmute_copy(&info.BaseAddress));
                }
            }
        }

        if mem1.is_some() && mem2.is_some() {
            break;
        }

        // iter through region size
        unsafe { p = p.add(info.RegionSize) };
    }

    if mem1.is_none() {
        return Err(ProcessError::EmulationNotRunning);
    }

    Ok(EmuRAMAddresses {
        mem_1: mem1.unwrap_or_default(),
        mem_2: mem2.unwrap_or_default(),
    })
}
