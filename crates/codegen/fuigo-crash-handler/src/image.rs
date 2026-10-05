//! Locate the main executable image in the current process (normal context).
//!
//! Crash blobs store absolute instruction pointers, but symbolication runs
//! in the NEXT process, whose image is mapped at a different address under
//! ASLR. At install time we record where the image containing this crate is
//! mapped (base, extent) and an identity of the binary, so the reader can
//! turn each in-image pointer into a module-relative offset and re-base it
//! into its own address space — and refuse to do so for a different build.
//!
//! None of this runs in a signal handler: the handler only copies values
//! computed here.

use crate::format::{BUILD_ID_LEN, ImageInfo};

/// An address inside this crate's code, used to pick the image that holds it.
#[inline(never)]
fn anchor() -> usize {
    anchor as *const () as usize
}

/// Locate the main image of the current process. `None` when the platform
/// does not support it or the lookup fails.
///
/// The identity is the GNU build id (Linux), `LC_UUID` (macOS) or the PE
/// timestamp + image size (Windows). A binary without one gets an all-zero
/// identity, and the reader then keeps raw offsets (`UnverifiedBuild`)
/// rather than guess: no partial file fingerprint is trusted.
pub fn current_image() -> Option<ImageInfo> {
    imp::current_image(anchor())
}

/// Size of the running executable file, `0` when unknown. Part of the build
/// identity check alongside the build id and image span.
pub fn current_exe_len() -> u64 {
    // On Linux `/proc/self/exe` resolves to the mapped inode even after the
    // file on disk was replaced (e.g. by an update while running).
    #[cfg(target_os = "linux")]
    if let Ok(m) = std::fs::metadata("/proc/self/exe") {
        return m.len();
    }
    std::env::current_exe()
        .and_then(std::fs::metadata)
        .map(|m| m.len())
        .unwrap_or(0)
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{BUILD_ID_LEN, ImageInfo};

    const PT_LOAD: u32 = 1;
    const PT_NOTE: u32 = 4;
    const NT_GNU_BUILD_ID: u32 = 3;

    struct Search {
        target: usize,
        found: Option<ImageInfo>,
    }

    unsafe fn read_build_id(base: usize, phdr: &libc::Elf64_Phdr) -> Option<[u8; BUILD_ID_LEN]> {
        let start = base.wrapping_add(phdr.p_vaddr as usize);
        let size = phdr.p_memsz as usize;
        let mut off = 0usize;
        let align4 = |n: usize| (n + 3) & !3;
        while off + 12 <= size {
            let p = (start + off) as *const u32;
            let (namesz, descsz, ntype) = unsafe {
                (
                    p.read_unaligned() as usize,
                    p.add(1).read_unaligned() as usize,
                    p.add(2).read_unaligned(),
                )
            };
            let name_at = off + 12;
            let desc_at = name_at + align4(namesz);
            let next = desc_at + align4(descsz);
            if next > size {
                break;
            }
            if ntype == NT_GNU_BUILD_ID && namesz == 4 {
                let name = unsafe { std::slice::from_raw_parts((start + name_at) as *const u8, 4) };
                if name == b"GNU\0" && descsz > 0 {
                    let desc = unsafe {
                        std::slice::from_raw_parts((start + desc_at) as *const u8, descsz)
                    };
                    let mut id = [0u8; BUILD_ID_LEN];
                    let n = descsz.min(BUILD_ID_LEN);
                    id[..n].copy_from_slice(&desc[..n]);
                    return Some(id);
                }
            }
            off = next;
        }
        None
    }

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        unsafe {
            let search = &mut *(data as *mut Search);
            let info = &*info;
            if info.dlpi_phdr.is_null() {
                return 0;
            }
            let base = info.dlpi_addr as usize;
            let phdrs = std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);
            let mut lo = usize::MAX;
            let mut hi = 0usize;
            let mut contains = false;
            for ph in phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
                let s = base.wrapping_add(ph.p_vaddr as usize);
                let e = s.wrapping_add(ph.p_memsz as usize);
                lo = lo.min(s);
                hi = hi.max(e);
                if s <= search.target && search.target < e {
                    contains = true;
                }
            }
            if !contains || lo >= hi {
                return 0;
            }
            let build_id = phdrs
                .iter()
                .filter(|p| p.p_type == PT_NOTE)
                .find_map(|p| read_build_id(base, p))
                .unwrap_or([0; BUILD_ID_LEN]);
            search.found = Some(ImageInfo {
                base: base as u64,
                lo: lo as u64,
                hi: hi as u64,
                build_id,
            });
            1
        }
    }

    pub(super) fn current_image(target: usize) -> Option<ImageInfo> {
        let mut search = Search {
            target,
            found: None,
        };
        unsafe {
            libc::dl_iterate_phdr(
                Some(callback),
                &mut search as *mut Search as *mut libc::c_void,
            );
        }
        search.found
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use super::{BUILD_ID_LEN, ImageInfo};

    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;

    #[repr(C)]
    struct MachHeader64 {
        magic: u32,
        cputype: i32,
        cpusubtype: i32,
        filetype: u32,
        ncmds: u32,
        sizeofcmds: u32,
        flags: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct LoadCommand {
        cmd: u32,
        cmdsize: u32,
    }

    #[repr(C)]
    struct SegmentCommand64 {
        cmd: u32,
        cmdsize: u32,
        segname: [u8; 16],
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        maxprot: i32,
        initprot: i32,
        nsects: u32,
        flags: u32,
    }

    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_header(image_index: u32) -> *const libc::c_void;
        fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    }

    pub(super) fn current_image(target: usize) -> Option<ImageInfo> {
        unsafe {
            let mut dl: libc::Dl_info = std::mem::zeroed();
            if libc::dladdr(target as *const libc::c_void, &mut dl) == 0 || dl.dli_fbase.is_null() {
                return None;
            }
            let header = dl.dli_fbase as *const MachHeader64;
            if (*header).magic != MH_MAGIC_64 {
                return None;
            }
            let mut slide: Option<isize> = None;
            for i in 0.._dyld_image_count() {
                if std::ptr::eq(
                    _dyld_get_image_header(i),
                    dl.dli_fbase as *const libc::c_void,
                ) {
                    slide = Some(_dyld_get_image_vmaddr_slide(i));
                    break;
                }
            }
            let slide = slide? as u64;

            let mut lo = u64::MAX;
            let mut hi = 0u64;
            let mut build_id = [0u8; BUILD_ID_LEN];
            let mut cmd_ptr = (header as *const u8).add(std::mem::size_of::<MachHeader64>());
            let end = cmd_ptr.add((*header).sizeofcmds as usize);
            for _ in 0..(*header).ncmds {
                if cmd_ptr.add(std::mem::size_of::<LoadCommand>()) > end {
                    break;
                }
                let lc = &*(cmd_ptr as *const LoadCommand);
                if lc.cmdsize == 0 {
                    break;
                }
                if lc.cmd == LC_SEGMENT_64 {
                    let seg = &*(cmd_ptr as *const SegmentCommand64);
                    // Skip __PAGEZERO (no access, maps nothing of the image).
                    if seg.initprot != 0 && seg.vmsize != 0 {
                        lo = lo.min(seg.vmaddr.wrapping_add(slide));
                        hi = hi.max(seg.vmaddr.wrapping_add(seg.vmsize).wrapping_add(slide));
                    }
                } else if lc.cmd == LC_UUID && lc.cmdsize as usize >= 8 + BUILD_ID_LEN {
                    let uuid = std::slice::from_raw_parts(cmd_ptr.add(8), BUILD_ID_LEN);
                    build_id.copy_from_slice(uuid);
                }
                cmd_ptr = cmd_ptr.add(lc.cmdsize as usize);
            }
            if lo >= hi {
                return None;
            }
            Some(ImageInfo {
                base: slide,
                lo,
                hi,
                build_id,
            })
        }
    }
}

#[cfg(windows)]
mod imp {
    use super::{BUILD_ID_LEN, ImageInfo};

    const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: u32 = 0x2;
    const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: u32 = 0x4;

    pub(super) fn current_image(target: usize) -> Option<ImageInfo> {
        unsafe {
            let mut module: windows_sys::Win32::Foundation::HMODULE = std::ptr::null_mut();
            let ok = windows_sys::Win32::System::LibraryLoader::GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
                    | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                target as *const u16,
                &mut module,
            );
            if ok == 0 || module.is_null() {
                return None;
            }
            let base = module as usize;
            // IMAGE_DOS_HEADER.e_lfanew at 0x3C → IMAGE_NT_HEADERS64.
            let dos_magic = (base as *const u16).read_unaligned();
            if dos_magic != 0x5A4D {
                return None;
            }
            let e_lfanew = ((base + 0x3C) as *const u32).read_unaligned() as usize;
            let nt = base + e_lfanew;
            if (nt as *const u32).read_unaligned() != 0x0000_4550 {
                return None;
            }
            // IMAGE_FILE_HEADER (20 bytes) follows the 4-byte signature;
            // TimeDateStamp is at +4 inside it. SizeOfImage is at +56 in the
            // optional header, which starts at nt + 24.
            let timestamp = ((nt + 4 + 4) as *const u32).read_unaligned();
            let size_of_image = ((nt + 24 + 56) as *const u32).read_unaligned();
            if size_of_image == 0 {
                return None;
            }
            let mut build_id = [0u8; BUILD_ID_LEN];
            if super::pe_timestamp_is_meaningful(timestamp) {
                build_id[..4].copy_from_slice(&timestamp.to_le_bytes());
                build_id[4..8].copy_from_slice(&size_of_image.to_le_bytes());
            }
            Some(ImageInfo {
                base: base as u64,
                lo: base as u64,
                hi: base as u64 + size_of_image as u64,
                build_id,
            })
        }
    }
}

/// The PE spec calls a TimeDateStamp of 0 or 0xFFFFFFFF "not meaningful";
/// such a binary gets an all-zero identity, so the reader keeps raw offsets.
#[cfg_attr(not(windows), allow(dead_code))]
fn pe_timestamp_is_meaningful(stamp: u32) -> bool {
    stamp != 0 && stamp != u32::MAX
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use super::ImageInfo;
    pub(super) fn current_image(_target: usize) -> Option<ImageInfo> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[test]
    fn current_image_contains_this_crate_code() {
        let img = current_image().expect("main image must be locatable");
        let here = current_image_contains_this_crate_code as *const () as u64;
        assert!(img.contains(here), "image {img:?} must contain {here:#x}");
        assert!(img.span() > 0);
        assert!(img.base <= img.lo, "base is at or below the first segment");
    }

    #[test]
    fn pe_sentinel_timestamps_carry_no_identity() {
        assert!(!pe_timestamp_is_meaningful(0));
        assert!(!pe_timestamp_is_meaningful(u32::MAX));
        assert!(pe_timestamp_is_meaningful(0x6512_3456));
    }

    #[test]
    fn exe_len_is_known() {
        assert!(current_exe_len() > 0);
    }
}
