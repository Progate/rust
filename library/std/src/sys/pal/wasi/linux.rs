//! The Linux system call entry of BrowserOS (`browser_os_linux.syscall`).
//!
//! Paths and the working directory belong to the kernel, as on Linux: relative paths are resolved
//! against the kernel's working directory (`AT_FDCWD`), and `chdir`/`getcwd` change and read it.
//! WASI preview1 has no such notion (wasi-libc emulates a working directory on top of pre-opened
//! directories), so the filesystem operations of std call the kernel through this entry instead.
//!
//! The entry takes the riscv32 (asm-generic) syscall numbers and returns `-errno` with Linux errno
//! values. Errors are translated to the WASI errno values that the rest of std uses.
//!
//! `sys::fs::unix` and `sys::paths::wasi` call the C library through [`libc`], which is the `libc`
//! crate with the path functions replaced by ones that go through this entry. They keep the
//! wasi-libc ABI (flags, `struct stat`, `struct dirent`, errno), so the callers are unchanged.
//! Operations on file descriptors (read, write, seek, close, ...) stay on wasi-libc: the kernel
//! hands out the descriptors and preview1 uses the same table.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::io;

#[link(wasm_import_module = "browser_os_linux")]
unsafe extern "C" {
    #[link_name = "syscall"]
    fn linux_syscall(nr: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64;
}

// Syscall numbers (asm-generic/unistd.h).
pub const SYS_GETCWD: i32 = 17;
pub const SYS_FCNTL64: i32 = 25;
pub const SYS_MKDIRAT: i32 = 34;
pub const SYS_UNLINKAT: i32 = 35;
pub const SYS_SYMLINKAT: i32 = 36;
pub const SYS_LINKAT: i32 = 37;
pub const SYS_CHDIR: i32 = 49;
pub const SYS_FCHMOD: i32 = 52;
pub const SYS_FCHMODAT: i32 = 53;
pub const SYS_OPENAT: i32 = 56;
pub const SYS_GETDENTS64: i32 = 61;
pub const SYS_READLINKAT: i32 = 78;
pub const SYS_GETPID: i32 = 172;
pub const SYS_RENAMEAT2: i32 = 276;
pub const SYS_STATX: i32 = 291;
pub const SYS_UTIMENSAT_TIME64: i32 = 412;

// Flags (asm-generic/fcntl.h, linux/fcntl.h, linux/stat.h).
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;
pub const AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const O_WRONLY: i32 = 0o1;
pub const O_RDWR: i32 = 0o2;
pub const O_CREAT: i32 = 0o100;
pub const O_EXCL: i32 = 0o200;
pub const O_TRUNC: i32 = 0o1000;
pub const O_APPEND: i32 = 0o2000;
pub const O_NONBLOCK: i32 = 0o4000;
pub const O_DSYNC: i32 = 0o10000;
pub const O_SYNC: i32 = 0o4010000;
pub const O_DIRECTORY: i32 = 0o200000;
pub const O_NOFOLLOW: i32 = 0o400000;
pub const O_CLOEXEC: i32 = 0o2000000;
pub const F_DUPFD_CLOEXEC: i32 = 1030;
pub const STATX_BASIC_STATS: u32 = 0x7ff;
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;
/// linux/limits.h
pub const PATH_MAX: usize = 4096;

// Linux errno values used here.
pub const ENOENT: i32 = 2;
pub const ELOOP: i32 = 40;

/// Calls a system call. Returns the non-negative result, or the Linux errno.
pub fn raw(nr: i32, args: [i64; 6]) -> Result<i64, i32> {
    // SAFETY: the callers pass pointers to memory that stays alive for the call.
    let result = unsafe { linux_syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
    // As on riscv32, the result is the low 32 bits (a negative errno included). The kernel may set
    // the high bits to tell a libc that handles signals that some are queued; std does not.
    let result = result as i32;
    if result < 0 && result >= -4095 { Err(-result) } else { Ok(result as i64) }
}

/// Calls a system call. Errors become `io::Error` with WASI errno values.
pub fn call(nr: i32, args: [i64; 6]) -> io::Result<i64> {
    raw(nr, args).map_err(error)
}

/// The `io::Error` of a Linux errno.
pub fn error(linux: i32) -> io::Error {
    io::Error::from_raw_os_error(wasi_errno(linux))
}

/// A pointer as a system call argument (wasm32 pointers are 32 bits).
pub fn ptr<T: ?Sized>(pointer: *const T) -> i64 {
    pointer.cast::<u8>() as usize as i64
}

/// getpid(2).
pub fn getpid() -> u32 {
    raw(SYS_GETPID, [0; 6]).unwrap_or(0) as u32
}

/// Duplicates a descriptor at 3 or above, with close-on-exec (`fcntl(F_DUPFD_CLOEXEC)`).
pub fn dup_cloexec(fd: i32) -> io::Result<i32> {
    call(SYS_FCNTL64, [fd as i64, F_DUPFD_CLOEXEC as i64, 3, 0, 0, 0]).map(|fd| fd as i32)
}

/// Translates a Linux errno into the WASI errno that std reports.
fn wasi_errno(linux: i32) -> i32 {
    use ::libc::*;
    match linux {
        1 => EPERM,
        2 => ENOENT,
        3 => ESRCH,
        4 => EINTR,
        5 => EIO,
        6 => ENXIO,
        7 => E2BIG,
        8 => ENOEXEC,
        9 => EBADF,
        10 => ECHILD,
        11 => EAGAIN,
        12 => ENOMEM,
        13 => EACCES,
        14 => EFAULT,
        16 => EBUSY,
        17 => EEXIST,
        18 => EXDEV,
        19 => ENODEV,
        20 => ENOTDIR,
        21 => EISDIR,
        22 => EINVAL,
        23 => ENFILE,
        24 => EMFILE,
        25 => ENOTTY,
        26 => ETXTBSY,
        27 => EFBIG,
        28 => ENOSPC,
        29 => ESPIPE,
        30 => EROFS,
        31 => EMLINK,
        32 => EPIPE,
        33 => EDOM,
        34 => ERANGE,
        35 => EDEADLK,
        36 => ENAMETOOLONG,
        37 => ENOLCK,
        38 => ENOSYS,
        39 => ENOTEMPTY,
        40 => ELOOP,
        42 => ENOMSG,
        43 => EIDRM,
        67 => ENOLINK,
        71 => EPROTO,
        72 => EMULTIHOP,
        74 => EBADMSG,
        75 => EOVERFLOW,
        84 => EILSEQ,
        88 => ENOTSOCK,
        89 => EDESTADDRREQ,
        90 => EMSGSIZE,
        91 => EPROTOTYPE,
        92 => ENOPROTOOPT,
        93 => EPROTONOSUPPORT,
        95 => ENOTSUP,
        97 => EAFNOSUPPORT,
        98 => EADDRINUSE,
        99 => EADDRNOTAVAIL,
        100 => ENETDOWN,
        101 => ENETUNREACH,
        102 => ENETRESET,
        103 => ECONNABORTED,
        104 => ECONNRESET,
        105 => ENOBUFS,
        106 => EISCONN,
        107 => ENOTCONN,
        110 => ETIMEDOUT,
        111 => ECONNREFUSED,
        113 => EHOSTUNREACH,
        114 => EALREADY,
        115 => EINPROGRESS,
        116 => ESTALE,
        122 => EDQUOT,
        125 => ECANCELED,
        130 => EOWNERDEAD,
        131 => ENOTRECOVERABLE,
        _ => EIO,
    }
}

/// The `libc` crate, with the functions that take paths (and the directory streams) going through
/// the kernel. Each one keeps the C signature and the wasi-libc ABI: `-1` and `errno` on failure.
#[allow(non_camel_case_types)]
pub mod libc {
    pub use ::libc::*;

    use crate::ffi::CStr;
    use crate::sys::pal::linux;
    use crate::{mem, ptr, slice};

    /// Stores the errno of a failed call and returns `-1`.
    fn fail(errno: i32) -> c_int {
        crate::sys::io::set_errno(linux::wasi_errno(errno));
        -1
    }

    fn int(result: Result<i64, i32>) -> c_int {
        match result {
            Ok(value) => value as c_int,
            Err(errno) => fail(errno),
        }
    }

    fn dirfd_of(fd: c_int) -> i64 {
        if fd == ::libc::AT_FDCWD { linux::AT_FDCWD as i64 } else { fd as i64 }
    }

    /// wasi-libc's `O_*` to Linux's.
    fn open_flags(flags: c_int) -> i32 {
        let access = flags & ::libc::O_RDWR;
        let mut bits = if access == ::libc::O_RDWR {
            linux::O_RDWR
        } else if access == ::libc::O_WRONLY {
            linux::O_WRONLY
        } else {
            0
        };
        for (wasi, bit) in [
            (::libc::O_APPEND, linux::O_APPEND),
            (::libc::O_DSYNC, linux::O_DSYNC),
            (::libc::O_NONBLOCK, linux::O_NONBLOCK),
            (::libc::O_RSYNC, linux::O_SYNC),
            (::libc::O_SYNC, linux::O_SYNC),
            (::libc::O_CREAT, linux::O_CREAT),
            (::libc::O_DIRECTORY, linux::O_DIRECTORY),
            (::libc::O_EXCL, linux::O_EXCL),
            (::libc::O_TRUNC, linux::O_TRUNC),
            (::libc::O_NOFOLLOW, linux::O_NOFOLLOW),
        ] {
            if flags & wasi != 0 {
                bits |= bit;
            }
        }
        // wasi-libc has no close-on-exec flag (`O_CLOEXEC` is 0); std always asks for it.
        bits | linux::O_CLOEXEC
    }

    /// wasi-libc's `AT_*` to Linux's.
    fn at_flags(flags: c_int) -> i32 {
        let mut bits = 0;
        for (wasi, bit) in [
            (::libc::AT_SYMLINK_NOFOLLOW, linux::AT_SYMLINK_NOFOLLOW),
            (::libc::AT_SYMLINK_FOLLOW, linux::AT_SYMLINK_FOLLOW),
            (::libc::AT_REMOVEDIR, linux::AT_REMOVEDIR),
        ] {
            if flags & wasi != 0 {
                bits |= bit;
            }
        }
        bits
    }

    pub unsafe fn open(path: *const c_char, flags: c_int, mode: c_int) -> c_int {
        unsafe { openat(::libc::AT_FDCWD, path, flags, mode) }
    }

    pub unsafe fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: c_int) -> c_int {
        int(linux::raw(
            linux::SYS_OPENAT,
            [dirfd_of(dirfd), linux::ptr(path), open_flags(flags) as i64, mode as i64, 0, 0],
        ))
    }

    /// `struct statx` (linux/stat.h): 256 bytes, the fields read below at their offsets.
    #[repr(C, align(8))]
    struct Statx([u8; 256]);

    impl Statx {
        fn u16(&self, offset: usize) -> u16 {
            u16::from_le_bytes([self.0[offset], self.0[offset + 1]])
        }

        fn u32(&self, offset: usize) -> u32 {
            u32::from_le_bytes(self.0[offset..offset + 4].try_into().unwrap())
        }

        fn u64(&self, offset: usize) -> u64 {
            u64::from_le_bytes(self.0[offset..offset + 8].try_into().unwrap())
        }

        /// A `struct statx_timestamp`.
        fn timestamp(&self, offset: usize) -> timespec {
            timespec { tv_sec: self.u64(offset) as i64, tv_nsec: self.u32(offset + 8) as _ }
        }

        /// makedev(3) of a major and minor pair.
        fn dev(&self, offset: usize) -> u64 {
            let major = self.u32(offset) as u64;
            let minor = self.u32(offset + 4) as u64;
            ((major & 0xfffff000) << 32)
                | ((major & 0xfff) << 8)
                | ((minor & 0xffffff00) << 12)
                | (minor & 0xff)
        }

        fn write_to(&self, buf: &mut stat) {
            // The file type bits (`S_IF*`) of wasi-libc are those of Linux.
            buf.st_dev = self.dev(0x88);
            buf.st_ino = self.u64(0x20);
            buf.st_nlink = self.u32(0x10) as _;
            buf.st_mode = self.u16(0x1c) as mode_t;
            buf.st_uid = self.u32(0x14);
            buf.st_gid = self.u32(0x18);
            buf.st_rdev = self.dev(0x80);
            buf.st_size = self.u64(0x28) as _;
            buf.st_blksize = self.u32(0x04) as _;
            buf.st_blocks = self.u64(0x30) as _;
            buf.st_atim = self.timestamp(0x40);
            buf.st_ctim = self.timestamp(0x60);
            buf.st_mtim = self.timestamp(0x70);
        }
    }

    fn statx(dirfd: i64, path: *const c_char, flags: i32, buf: *mut stat) -> c_int {
        let mut statx = Statx([0; 256]);
        match linux::raw(
            linux::SYS_STATX,
            [
                dirfd,
                linux::ptr(path),
                flags as i64,
                linux::STATX_BASIC_STATS as i64,
                linux::ptr(&raw mut statx),
                0,
            ],
        ) {
            Ok(_) => {
                // SAFETY: the callers pass a valid `struct stat`.
                statx.write_to(unsafe { &mut *buf });
                0
            }
            Err(errno) => fail(errno),
        }
    }

    pub unsafe fn stat(path: *const c_char, buf: *mut stat) -> c_int {
        statx(linux::AT_FDCWD as i64, path, 0, buf)
    }

    pub unsafe fn lstat(path: *const c_char, buf: *mut stat) -> c_int {
        statx(linux::AT_FDCWD as i64, path, linux::AT_SYMLINK_NOFOLLOW, buf)
    }

    pub unsafe fn fstat(fd: c_int, buf: *mut stat) -> c_int {
        statx(fd as i64, c"".as_ptr(), linux::AT_EMPTY_PATH, buf)
    }

    pub unsafe fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
        int(linux::raw(
            linux::SYS_MKDIRAT,
            [linux::AT_FDCWD as i64, linux::ptr(path), mode as i64, 0, 0, 0],
        ))
    }

    pub unsafe fn unlinkat(dirfd: c_int, path: *const c_char, flags: c_int) -> c_int {
        int(linux::raw(
            linux::SYS_UNLINKAT,
            [dirfd_of(dirfd), linux::ptr(path), at_flags(flags) as i64, 0, 0, 0],
        ))
    }

    pub unsafe fn unlink(path: *const c_char) -> c_int {
        unsafe { unlinkat(::libc::AT_FDCWD, path, 0) }
    }

    pub unsafe fn rmdir(path: *const c_char) -> c_int {
        unsafe { unlinkat(::libc::AT_FDCWD, path, ::libc::AT_REMOVEDIR) }
    }

    pub unsafe fn rename(old: *const c_char, new: *const c_char) -> c_int {
        int(linux::raw(
            linux::SYS_RENAMEAT2,
            [
                linux::AT_FDCWD as i64,
                linux::ptr(old),
                linux::AT_FDCWD as i64,
                linux::ptr(new),
                0,
                0,
            ],
        ))
    }

    pub unsafe fn linkat(
        olddirfd: c_int,
        old: *const c_char,
        newdirfd: c_int,
        new: *const c_char,
        flags: c_int,
    ) -> c_int {
        int(linux::raw(
            linux::SYS_LINKAT,
            [
                dirfd_of(olddirfd),
                linux::ptr(old),
                dirfd_of(newdirfd),
                linux::ptr(new),
                at_flags(flags) as i64,
                0,
            ],
        ))
    }


    pub unsafe fn symlink(target: *const c_char, link: *const c_char) -> c_int {
        int(linux::raw(
            linux::SYS_SYMLINKAT,
            [linux::ptr(target), linux::AT_FDCWD as i64, linux::ptr(link), 0, 0, 0],
        ))
    }

    pub unsafe fn readlink(path: *const c_char, buf: *mut c_char, size: size_t) -> ssize_t {
        match linux::raw(
            linux::SYS_READLINKAT,
            [linux::AT_FDCWD as i64, linux::ptr(path), linux::ptr(buf), size as i64, 0, 0],
        ) {
            Ok(len) => len as ssize_t,
            Err(errno) => fail(errno) as ssize_t,
        }
    }

    pub unsafe fn chmod(path: *const c_char, mode: mode_t) -> c_int {
        int(linux::raw(
            linux::SYS_FCHMODAT,
            [linux::AT_FDCWD as i64, linux::ptr(path), mode as i64, 0, 0, 0],
        ))
    }

    pub unsafe fn fchmod(fd: c_int, mode: mode_t) -> c_int {
        int(linux::raw(linux::SYS_FCHMOD, [fd as i64, mode as i64, 0, 0, 0, 0]))
    }

    /// The `struct timespec` of utimensat(2) on riscv32 (64-bit `tv_sec`, `tv_nsec` padded to 64).
    #[repr(C)]
    struct Timespec64 {
        tv_sec: i64,
        tv_nsec: i64,
    }

    pub unsafe fn utimensat(
        dirfd: c_int,
        path: *const c_char,
        times: *const timespec,
        flags: c_int,
    ) -> c_int {
        let convert = |time: &timespec| Timespec64 {
            tv_sec: time.tv_sec,
            tv_nsec: match time.tv_nsec {
                ::libc::UTIME_NOW => linux::UTIME_NOW,
                ::libc::UTIME_OMIT => linux::UTIME_OMIT,
                nsec => nsec as i64,
            },
        };
        // SAFETY: the callers pass two timestamps.
        let times = unsafe { [convert(&*times), convert(&*times.add(1))] };
        int(linux::raw(
            linux::SYS_UTIMENSAT_TIME64,
            [
                dirfd_of(dirfd),
                linux::ptr(path),
                linux::ptr(times.as_ptr()),
                at_flags(flags) as i64,
                0,
                0,
            ],
        ))
    }

    pub unsafe fn getcwd(buf: *mut c_char, size: size_t) -> *mut c_char {
        match linux::raw(linux::SYS_GETCWD, [linux::ptr(buf), size as i64, 0, 0, 0, 0]) {
            Ok(_) => buf,
            Err(errno) => {
                fail(errno);
                ptr::null_mut()
            }
        }
    }

    pub unsafe fn chdir(path: *const c_char) -> c_int {
        int(linux::raw(linux::SYS_CHDIR, [linux::ptr(path), 0, 0, 0, 0, 0]))
    }

    /// realpath(3), resolved the way musl does it: walk the components from the root (or the
    /// working directory), following symbolic links, with at most 40 of them (ELOOP).
    pub unsafe fn realpath(path: *const c_char, resolved: *mut c_char) -> *mut c_char {
        // SAFETY: the callers pass a C string.
        let path = unsafe { CStr::from_ptr(path) }.to_bytes();
        let result = match canonicalize(path) {
            Ok(result) => result,
            Err(errno) => {
                fail(errno);
                return ptr::null_mut();
            }
        };
        let out = if resolved.is_null() {
            // SAFETY: the caller frees it with free(3).
            let out = unsafe { ::libc::malloc(result.len() + 1) }.cast::<c_char>();
            if out.is_null() {
                crate::sys::io::set_errno(::libc::ENOMEM);
                return ptr::null_mut();
            }
            out
        } else if result.len() >= linux::PATH_MAX {
            fail(36); // ENAMETOOLONG
            return ptr::null_mut();
        } else {
            resolved
        };
        // SAFETY: `out` has room for the path and the NUL.
        unsafe {
            ptr::copy_nonoverlapping(result.as_ptr().cast::<c_char>(), out, result.len());
            *out.add(result.len()) = 0;
        }
        out
    }

    fn canonicalize(path: &[u8]) -> Result<Vec<u8>, i32> {
        const MAX_LINKS: usize = 40;

        if path.is_empty() {
            return Err(linux::ENOENT);
        }
        let mut resolved: Vec<Vec<u8>> = Vec::new();
        let mut pending: crate::collections::VecDeque<Vec<u8>> = Default::default();
        if path[0] != b'/' {
            let mut cwd = vec![0u8; linux::PATH_MAX];
            let len = linux::raw(
                linux::SYS_GETCWD,
                [linux::ptr(cwd.as_mut_ptr()), cwd.len() as i64, 0, 0, 0, 0],
            )?;
            cwd.truncate((len as usize).saturating_sub(1));
            pending.extend(split(&cwd));
        }
        pending.extend(split(path));

        let mut links = 0;
        while let Some(name) = pending.pop_front() {
            if name == b"." {
                continue;
            }
            if name == b".." {
                resolved.pop();
                continue;
            }
            let mut candidate = join(&resolved);
            if candidate.len() > 1 {
                candidate.push(b'/');
            }
            candidate.extend_from_slice(&name);
            candidate.push(0);

            let mut statx = Statx([0; 256]);
            linux::raw(
                linux::SYS_STATX,
                [
                    linux::AT_FDCWD as i64,
                    linux::ptr(candidate.as_ptr()),
                    linux::AT_SYMLINK_NOFOLLOW as i64,
                    linux::STATX_BASIC_STATS as i64,
                    linux::ptr(&raw mut statx),
                    0,
                ],
            )?;
            if statx.u16(0x1c) as mode_t & ::libc::S_IFMT != ::libc::S_IFLNK {
                resolved.push(name);
                continue;
            }
            links += 1;
            if links > MAX_LINKS {
                return Err(linux::ELOOP);
            }
            let mut target = vec![0u8; linux::PATH_MAX];
            let len = linux::raw(
                linux::SYS_READLINKAT,
                [
                    linux::AT_FDCWD as i64,
                    linux::ptr(candidate.as_ptr()),
                    linux::ptr(target.as_mut_ptr()),
                    target.len() as i64,
                    0,
                    0,
                ],
            )?;
            target.truncate(len as usize);
            if target.first() == Some(&b'/') {
                resolved.clear();
            }
            for component in split(&target).into_iter().rev() {
                pending.push_front(component);
            }
        }
        // realpath(3) fails when the result does not exist; the walk above has checked every
        // component.
        Ok(join(&resolved))
    }

    fn split(path: &[u8]) -> Vec<Vec<u8>> {
        path.split(|&b| b == b'/').filter(|c| !c.is_empty()).map(|c| c.to_vec()).collect()
    }

    fn join(components: &[Vec<u8>]) -> Vec<u8> {
        let mut path = Vec::new();
        for component in components {
            path.push(b'/');
            path.extend_from_slice(component);
        }
        if path.is_empty() {
            path.push(b'/');
        }
        path
    }

    /// A directory stream read with getdents64(2). `DIR` is opaque to the callers.
    struct Dir {
        fd: c_int,
        /// `struct linux_dirent64` records from the kernel.
        buf: Vec<u64>,
        /// Bytes of `buf` filled, and the offset of the next record.
        len: usize,
        pos: usize,
        /// The wasi-libc `struct dirent` handed out by readdir (until the next call).
        entry: Vec<u64>,
    }

    pub unsafe fn fdopendir(fd: c_int) -> *mut DIR {
        let dir = Dir { fd, buf: vec![0; 4096 / 8], len: 0, pos: 0, entry: Vec::new() };
        Box::into_raw(Box::new(dir)).cast::<DIR>()
    }

    pub unsafe fn opendir(path: *const c_char) -> *mut DIR {
        let fd = unsafe { open(path, ::libc::O_RDONLY | ::libc::O_DIRECTORY, 0) };
        if fd < 0 {
            return ptr::null_mut();
        }
        unsafe { fdopendir(fd) }
    }

    pub unsafe fn dirfd(dir: *mut DIR) -> c_int {
        // SAFETY: `dir` came from fdopendir.
        unsafe { (*dir.cast::<Dir>()).fd }
    }

    pub unsafe fn closedir(dir: *mut DIR) -> c_int {
        // SAFETY: `dir` came from fdopendir and is not used again.
        let dir = unsafe { Box::from_raw(dir.cast::<Dir>()) };
        unsafe { ::libc::close(dir.fd) }
    }

    /// Returns the next entry; NULL with errno untouched at the end, NULL with errno on errors.
    pub unsafe fn readdir(dir: *mut DIR) -> *mut dirent {
        // SAFETY: `dir` came from fdopendir.
        let dir = unsafe { &mut *dir.cast::<Dir>() };
        if dir.pos >= dir.len {
            let size = dir.buf.len() * 8;
            match linux::raw(
                linux::SYS_GETDENTS64,
                [dir.fd as i64, linux::ptr(dir.buf.as_mut_ptr()), size as i64, 0, 0, 0],
            ) {
                Ok(0) => return ptr::null_mut(),
                Ok(read) => {
                    dir.len = read as usize;
                    dir.pos = 0;
                }
                Err(errno) => {
                    fail(errno);
                    return ptr::null_mut();
                }
            }
        }
        // SAFETY: the kernel has filled `len` bytes of `buf`.
        let bytes = unsafe { slice::from_raw_parts(dir.buf.as_ptr().cast::<u8>(), dir.len) };
        let record = &bytes[dir.pos..];
        let ino = u64::from_le_bytes(record[0..8].try_into().unwrap());
        let reclen = u16::from_le_bytes([record[16], record[17]]) as usize;
        let d_type = match record[18] {
            1 => ::libc::DT_FIFO,
            2 => ::libc::DT_CHR,
            4 => ::libc::DT_DIR,
            6 => ::libc::DT_BLK,
            8 => ::libc::DT_REG,
            10 => ::libc::DT_LNK,
            12 => ::libc::DT_SOCK,
            _ => ::libc::DT_UNKNOWN,
        };
        let name = &record[19..reclen];
        let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
        dir.pos += reclen;

        // `struct dirent` of wasi-libc: d_ino (u64), d_type (u8), then d_name with its NUL.
        let name_offset = mem::offset_of!(dirent, d_name);
        let size = name_offset + name.len() + 1;
        dir.entry.clear();
        dir.entry.resize(size.div_ceil(8), 0);
        let entry = dir.entry.as_mut_ptr().cast::<u8>();
        // SAFETY: `entry` has room for `size` bytes.
        unsafe {
            entry.cast::<u64>().write(ino);
            entry.add(mem::offset_of!(dirent, d_type)).write(d_type);
            ptr::copy_nonoverlapping(name.as_ptr(), entry.add(name_offset), name.len());
        }
        entry.cast::<dirent>()
    }
}
