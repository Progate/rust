//! The Linux system call entry of BrowserOS (`browser_os_linux.syscall`).
//!
//! Paths and the working directory belong to the kernel, as on Linux: relative paths are resolved
//! against the kernel's working directory (`AT_FDCWD`), and `chdir`/`getcwd` change and read it.
//! WASI preview1 has no such notion (wasi-libc emulates a working directory on top of pre-opened
//! directories), so the filesystem operations of std call the kernel through this entry instead.
//!
//! The entry takes the riscv32 (asm-generic) syscall numbers and returns `-errno` with Linux errno
//! values. Errors are translated to the WASI errno values that the rest of std uses.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::ffi::CStr;
use crate::io;

#[link(wasm_import_module = "browser_os_linux")]
extern "C" {
    #[link_name = "syscall"]
    fn linux_syscall(nr: i32, a0: i64, a1: i64, a2: i64, a3: i64, a4: i64, a5: i64) -> i64;
}

// Syscall numbers (asm-generic/unistd.h).
pub const SYS_GETCWD: i32 = 17;
pub const SYS_FCNTL64: i32 = 25;
pub const SYS_UNLINKAT: i32 = 35;
pub const SYS_SYMLINKAT: i32 = 36;
pub const SYS_LINKAT: i32 = 37;
pub const SYS_MKDIRAT: i32 = 34;
pub const SYS_CHDIR: i32 = 49;
pub const SYS_FCHMOD: i32 = 52;
pub const SYS_FCHMODAT: i32 = 53;
pub const SYS_OPENAT: i32 = 56;
pub const SYS_GETDENTS64: i32 = 61;
pub const SYS_READLINKAT: i32 = 78;
pub const SYS_RENAMEAT2: i32 = 276;
pub const SYS_STATX: i32 = 291;

// Flags (asm-generic/fcntl.h, linux/fcntl.h, linux/stat.h).
pub const AT_FDCWD: i32 = -100;
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
pub const AT_REMOVEDIR: i32 = 0x200;
pub const AT_EMPTY_PATH: i32 = 0x1000;
pub const O_RDONLY: i32 = 0o0;
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
pub const STATX_BTIME: u32 = 0x800;

// File types (`st_mode & S_IFMT`, and `d_type` of getdents64).
pub const S_IFMT: u32 = 0o170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const DT_UNKNOWN: u8 = 0;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_BLK: u8 = 6;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;
pub const DT_SOCK: u8 = 12;

// Linux errno values used by std itself.
pub const ERANGE: i32 = 34;

/// Calls a system call. Returns the non-negative result, or the Linux errno.
pub fn raw(nr: i32, args: [i64; 6]) -> Result<i64, i32> {
    // SAFETY: the callers pass pointers to memory that stays alive for the call.
    let result =
        unsafe { linux_syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
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

/// A path as a system call argument.
pub fn path(path: &CStr) -> i64 {
    ptr(path.as_ptr())
}

/// Translates a Linux errno into the WASI errno that std reports.
fn wasi_errno(linux: i32) -> i32 {
    let errno = match linux {
        1 => wasi::ERRNO_PERM,
        2 => wasi::ERRNO_NOENT,
        3 => wasi::ERRNO_SRCH,
        4 => wasi::ERRNO_INTR,
        5 => wasi::ERRNO_IO,
        6 => wasi::ERRNO_NXIO,
        7 => wasi::ERRNO_2BIG,
        8 => wasi::ERRNO_NOEXEC,
        9 => wasi::ERRNO_BADF,
        10 => wasi::ERRNO_CHILD,
        11 => wasi::ERRNO_AGAIN,
        12 => wasi::ERRNO_NOMEM,
        13 => wasi::ERRNO_ACCES,
        14 => wasi::ERRNO_FAULT,
        16 => wasi::ERRNO_BUSY,
        17 => wasi::ERRNO_EXIST,
        18 => wasi::ERRNO_XDEV,
        19 => wasi::ERRNO_NODEV,
        20 => wasi::ERRNO_NOTDIR,
        21 => wasi::ERRNO_ISDIR,
        22 => wasi::ERRNO_INVAL,
        23 => wasi::ERRNO_NFILE,
        24 => wasi::ERRNO_MFILE,
        25 => wasi::ERRNO_NOTTY,
        26 => wasi::ERRNO_TXTBSY,
        27 => wasi::ERRNO_FBIG,
        28 => wasi::ERRNO_NOSPC,
        29 => wasi::ERRNO_SPIPE,
        30 => wasi::ERRNO_ROFS,
        31 => wasi::ERRNO_MLINK,
        32 => wasi::ERRNO_PIPE,
        33 => wasi::ERRNO_DOM,
        34 => wasi::ERRNO_RANGE,
        35 => wasi::ERRNO_DEADLK,
        36 => wasi::ERRNO_NAMETOOLONG,
        37 => wasi::ERRNO_NOLCK,
        38 => wasi::ERRNO_NOSYS,
        39 => wasi::ERRNO_NOTEMPTY,
        40 => wasi::ERRNO_LOOP,
        42 => wasi::ERRNO_NOMSG,
        43 => wasi::ERRNO_IDRM,
        67 => wasi::ERRNO_NOLINK,
        71 => wasi::ERRNO_PROTO,
        72 => wasi::ERRNO_MULTIHOP,
        74 => wasi::ERRNO_BADMSG,
        75 => wasi::ERRNO_OVERFLOW,
        84 => wasi::ERRNO_ILSEQ,
        88 => wasi::ERRNO_NOTSOCK,
        89 => wasi::ERRNO_DESTADDRREQ,
        90 => wasi::ERRNO_MSGSIZE,
        91 => wasi::ERRNO_PROTOTYPE,
        92 => wasi::ERRNO_NOPROTOOPT,
        93 => wasi::ERRNO_PROTONOSUPPORT,
        95 => wasi::ERRNO_NOTSUP,
        97 => wasi::ERRNO_AFNOSUPPORT,
        98 => wasi::ERRNO_ADDRINUSE,
        99 => wasi::ERRNO_ADDRNOTAVAIL,
        100 => wasi::ERRNO_NETDOWN,
        101 => wasi::ERRNO_NETUNREACH,
        102 => wasi::ERRNO_NETRESET,
        103 => wasi::ERRNO_CONNABORTED,
        104 => wasi::ERRNO_CONNRESET,
        105 => wasi::ERRNO_NOBUFS,
        106 => wasi::ERRNO_ISCONN,
        107 => wasi::ERRNO_NOTCONN,
        110 => wasi::ERRNO_TIMEDOUT,
        111 => wasi::ERRNO_CONNREFUSED,
        113 => wasi::ERRNO_HOSTUNREACH,
        114 => wasi::ERRNO_ALREADY,
        115 => wasi::ERRNO_INPROGRESS,
        116 => wasi::ERRNO_STALE,
        122 => wasi::ERRNO_DQUOT,
        125 => wasi::ERRNO_CANCELED,
        130 => wasi::ERRNO_OWNERDEAD,
        131 => wasi::ERRNO_NOTRECOVERABLE,
        _ => wasi::ERRNO_IO,
    };
    errno.raw().into()
}
