// dolphin-memory provides an API for hooking into dolphin and accessing runtime memory. It conveniently
// handles mapping of common data types, endian-ness, pointer chains and more. Accessing memory
// in this way is implicitly unsafe, but an effort is being made to ensure the API is as safe
// as it can be for use.

use std::ffi;
use std::io;
use std::mem;
use std::num::TryFromIntError;
use std::ptr;
use thiserror::Error;

use winapi::um::memoryapi;
use winapi::um::psapi;
use winapi::um::winnt;

use byteorder::{BigEndian, ReadBytesExt};
use process_memory::{CopyAddress, ProcessHandle, ProcessHandleExt, TryIntoProcessHandle};

// MEM1_STRIP_START is  useful for stripping the `8` from the start
// of memory addresses within the MEM1 region.
pub const MEM1_STRIP_START: usize = 0x3FFFFFFF;

pub const MEM1_START: usize = 0x10000000;
pub const MEM1_END: usize = 0x81800000;
pub const MEM1_SIZE: usize = 0x2000000;
pub const MEM2_SIZE: usize = 0x4000000;

#[derive(Error, Debug)]
pub enum ProcessError {
    #[error("failed to find process for dolphin")]
    DolphinNotFound,
    #[error("emulation not running")]
    EmulationNotRunning,
    #[error("unknown error")]
    UnknownError,
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
                .map_err(|_| ProcessError::UnknownError)?,
            None => return Err(ProcessError::DolphinNotFound),
        };

        let ram = ram_info(handle)?;
        let handle = handle.set_arch(process_memory::Architecture::Arch32Bit);

        Ok(Dolphin { handle, ram })
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

        if pointer_offsets.is_none() {
            let address = self
                .handle
                .get_offset(&[self.ram.mem_1 + starting_address])?;

            self.handle.copy_address(address, &mut buffer)?;

            return Ok(buffer);
        }

        if let Some(offsets) = pointer_offsets {
            // read the starting address to get the initial pointer.
            // we could have multiple pointer chains to follow, but we know the starting
            // address is where we want to look first to kick ourselves off on the right foot.
            let mut ptr_buffer = vec![0_u8; std::mem::size_of::<u32>()];
            self.handle
                .copy_address(self.ram.mem_1 + starting_address, &mut ptr_buffer)?;

            let mut current_ptr: usize = io::Cursor::new(ptr_buffer)
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
                    self.handle
                        .copy_address(self.ram.mem_1 + addr, &mut buffer)?;
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
        }

        Ok(buffer)
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
    unsafe {
        snapshot = winapi::um::tlhelp32::CreateToolhelp32Snapshot(
            winapi::um::tlhelp32::TH32CS_SNAPPROCESS,
            0,
        );

        if winapi::um::tlhelp32::Process32First(snapshot, &mut entry)
            == winapi::shared::minwindef::TRUE
        {
            while winapi::um::tlhelp32::Process32Next(snapshot, &mut entry)
                == winapi::shared::minwindef::TRUE
            {
                if process_names.contains(&utf8_to_string(&entry.szExeFile).as_str()) {
                    return Some(entry.th32ProcessID);
                }
            }
        }
    }

    None
}

// ram_info is a convenient function wrapper for querying the emulated GC heap addresses.
fn ram_info(process: ProcessHandle) -> Result<EmuRAMAddresses, ProcessError> {
    let mut info = winnt::MEMORY_BASIC_INFORMATION::default();
    let mut mem1_found = false;
    let mut mem2_found = false;
    let mut emu_ram_addresses = EmuRAMAddresses { mem_1: 0, mem_2: 0 };

    // TODO: this unsafe block is huge and complicated. It would be ideal to reign
    // this in a little to only cover the exact unsafe things that we need to cover.
    unsafe {
        let mut p = ptr::null_mut();
        loop {
            let size = memoryapi::VirtualQueryEx(
                process.0,
                p,
                &mut info,
                mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>(),
            );

            if size != mem::size_of::<winnt::MEMORY_BASIC_INFORMATION>() {
                break;
            }

            // check region size so that we know it's mem2
            if info.RegionSize == MEM2_SIZE {
                let region_base_address = info.BaseAddress as usize;

                if mem1_found && region_base_address > emu_ram_addresses.mem_1 + MEM1_START {
                    // in some cases MEM2 could actually be before MEM1. Once we find
                    // MEM1, ignore regions of this size that are too far away. There
                    // apparently are other non-MEM2 regions of size 0x40000000.
                    break;
                }

                // View the comment for MEM1
                let mut ws_info = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                    VirtualAddress: info.BaseAddress,
                    ..Default::default()
                };
                if psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                        .try_into()
                        .unwrap(),
                ) != 0
                    && ws_info.VirtualAttributes.Valid() == 1
                {
                    emu_ram_addresses.mem_2 = mem::transmute_copy(&info.BaseAddress);
                    mem2_found = true;
                }
            } else if !mem1_found && info.RegionSize == MEM1_SIZE && info.Type == winnt::MEM_MAPPED
            {
                // Here it's likely the right page, but it can happen that multiple pages
                // with these criteria exists and have nothing to do with emulated memory.
                // Only the right page has valid working set information so an additional
                // check is required that it is backed by physical memory.
                let mut ws_info_2 = psapi::PSAPI_WORKING_SET_EX_INFORMATION {
                    VirtualAddress: info.BaseAddress,
                    ..Default::default()
                };
                if psapi::QueryWorkingSetEx(
                    process.0,
                    &mut ws_info_2 as *mut _ as *mut ffi::c_void,
                    mem::size_of::<psapi::PSAPI_WORKING_SET_EX_INFORMATION>()
                        .try_into()
                        .unwrap(),
                ) != 0
                    && ws_info_2.VirtualAttributes.Valid() == 1
                {
                    emu_ram_addresses.mem_1 = mem::transmute_copy(&info.BaseAddress);
                    mem1_found = true;
                }
            }

            if mem1_found && mem2_found {
                break;
            }

            // iter through region size
            p = p.add(info.RegionSize);
        }
    }

    if emu_ram_addresses.mem_1 == 0 {
        return Err(ProcessError::EmulationNotRunning);
    }

    Ok(emu_ram_addresses)
}
