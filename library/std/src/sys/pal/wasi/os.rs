#![forbid(unsafe_op_in_unsafe_fn)]

use core::slice::memchr;

use crate::error::Error as StdError;
use crate::ffi::{CStr, OsStr, OsString};
use crate::ops::Drop;
use crate::os::wasi::prelude::*;
use crate::path::{self, PathBuf};
use crate::sys::common::small_c_string::{run_path_with_cstr, run_with_cstr};
use crate::{fmt, io, iter, slice, str, vec};

// Add a few symbols not in upstream `libc` just yet.
mod libc {
    pub use libc::*;

    extern "C" {
        pub fn __wasilibc_get_environ() -> *mut *mut c_char;
    }
}

cfg_if::cfg_if! {
    if #[cfg(target_feature = "atomics")] {
        // Access to the environment must be protected by a lock in multi-threaded scenarios.
        use crate::sync::{PoisonError, RwLock};
        static ENV_LOCK: RwLock<()> = RwLock::new(());
        pub fn env_read_lock() -> impl Drop {
            ENV_LOCK.read().unwrap_or_else(PoisonError::into_inner)
        }
        pub fn env_write_lock() -> impl Drop {
            ENV_LOCK.write().unwrap_or_else(PoisonError::into_inner)
        }
    } else {
        // No need for a lock if we are single-threaded.
        pub fn env_read_lock() -> impl Drop {
            Box::new(())
        }
        pub fn env_write_lock() -> impl Drop {
            Box::new(())
        }
    }
}

pub fn errno() -> i32 {
    extern "C" {
        #[thread_local]
        static errno: libc::c_int;
    }

    unsafe { errno as i32 }
}

pub fn error_string(errno: i32) -> String {
    let mut buf = [0 as libc::c_char; 1024];

    let p = buf.as_mut_ptr();
    unsafe {
        if libc::strerror_r(errno as libc::c_int, p, buf.len()) < 0 {
            panic!("strerror_r failure");
        }
        str::from_utf8(CStr::from_ptr(p).to_bytes()).unwrap().to_owned()
    }
}

/// getcwd(2). The working directory belongs to the kernel, as on Linux (see `linux.rs`).
pub fn getcwd() -> io::Result<PathBuf> {
    let mut buf = Vec::<u8>::with_capacity(512);
    loop {
        match super::linux::raw(
            super::linux::SYS_GETCWD,
            [super::linux::ptr(buf.as_mut_ptr()), buf.capacity() as i64, 0, 0, 0, 0],
        ) {
            Ok(len) => {
                // The kernel returns the length including the terminating NUL.
                // SAFETY: getcwd(2) has written `len` bytes.
                unsafe { buf.set_len((len as usize).saturating_sub(1)) };
                buf.shrink_to_fit();
                return Ok(PathBuf::from(OsString::from_vec(buf)));
            }
            Err(super::linux::ERANGE) => {
                // Trigger the internal buffer resizing logic of `Vec` by requiring
                // more space than the current capacity.
                let cap = buf.capacity();
                buf.reserve(cap + 1);
            }
            Err(errno) => return Err(super::linux::error(errno)),
        }
    }
}

/// chdir(2).
pub fn chdir(p: &path::Path) -> io::Result<()> {
    run_path_with_cstr(p, &|p| {
        super::linux::call(super::linux::SYS_CHDIR, [super::linux::path(p), 0, 0, 0, 0, 0])
            .map(drop)
    })
}

const PATH_SEPARATOR: u8 = b':';

pub struct SplitPaths<'a> {
    iter: iter::Map<slice::Split<'a, u8, fn(&u8) -> bool>, fn(&'a [u8]) -> PathBuf>,
}

pub fn split_paths(unparsed: &OsStr) -> SplitPaths<'_> {
    fn bytes_to_path(b: &[u8]) -> PathBuf {
        PathBuf::from(<OsStr as OsStrExt>::from_bytes(b))
    }
    fn is_separator(b: &u8) -> bool {
        *b == PATH_SEPARATOR
    }
    let unparsed = unparsed.as_bytes();
    SplitPaths {
        iter: unparsed
            .split(is_separator as fn(&u8) -> bool)
            .map(bytes_to_path as fn(&[u8]) -> PathBuf),
    }
}

impl<'a> Iterator for SplitPaths<'a> {
    type Item = PathBuf;
    fn next(&mut self) -> Option<PathBuf> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

#[derive(Debug)]
pub struct JoinPathsError;

pub fn join_paths<I, T>(paths: I) -> Result<OsString, JoinPathsError>
where
    I: Iterator<Item = T>,
    T: AsRef<OsStr>,
{
    let mut joined = Vec::new();

    for (i, path) in paths.enumerate() {
        let path = path.as_ref().as_bytes();
        if i > 0 {
            joined.push(PATH_SEPARATOR)
        }
        if path.contains(&PATH_SEPARATOR) {
            return Err(JoinPathsError);
        }
        joined.extend_from_slice(path);
    }
    Ok(OsStringExt::from_vec(joined))
}

impl fmt::Display for JoinPathsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "path segment contains separator `{}`", char::from(PATH_SEPARATOR))
    }
}

impl StdError for JoinPathsError {
    #[allow(deprecated)]
    fn description(&self) -> &str {
        "failed to join paths"
    }
}

pub fn current_exe() -> io::Result<PathBuf> {
    match crate::fs::read_link("/proc/self/exe") {
        Err(ref e) if e.kind() == io::ErrorKind::NotFound => Err(io::const_io_error!(
            io::ErrorKind::Uncategorized,
            "no /proc/self/exe available. Is /proc mounted?",
        )),
        other => other,
    }
}

pub struct Env {
    iter: vec::IntoIter<(OsString, OsString)>,
}

// FIXME(https://github.com/rust-lang/rust/issues/114583): Remove this when <OsStr as Debug>::fmt matches <str as Debug>::fmt.
pub struct EnvStrDebug<'a> {
    slice: &'a [(OsString, OsString)],
}

impl fmt::Debug for EnvStrDebug<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { slice } = self;
        f.debug_list()
            .entries(slice.iter().map(|(a, b)| (a.to_str().unwrap(), b.to_str().unwrap())))
            .finish()
    }
}

impl Env {
    pub fn str_debug(&self) -> impl fmt::Debug + '_ {
        let Self { iter } = self;
        EnvStrDebug { slice: iter.as_slice() }
    }
}

impl fmt::Debug for Env {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { iter } = self;
        f.debug_list().entries(iter.as_slice()).finish()
    }
}

impl !Send for Env {}
impl !Sync for Env {}

impl Iterator for Env {
    type Item = (OsString, OsString);
    fn next(&mut self) -> Option<(OsString, OsString)> {
        self.iter.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

pub fn env() -> Env {
    unsafe {
        let _guard = env_read_lock();

        // Use `__wasilibc_get_environ` instead of `environ` here so that we
        // don't require wasi-libc to eagerly initialize the environment
        // variables.
        let mut environ = libc::__wasilibc_get_environ();

        let mut result = Vec::new();
        if !environ.is_null() {
            while !(*environ).is_null() {
                if let Some(key_value) = parse(CStr::from_ptr(*environ).to_bytes()) {
                    result.push(key_value);
                }
                environ = environ.add(1);
            }
        }
        return Env { iter: result.into_iter() };
    }

    // See src/libstd/sys/pal/unix/os.rs, same as that
    fn parse(input: &[u8]) -> Option<(OsString, OsString)> {
        if input.is_empty() {
            return None;
        }
        let pos = memchr::memchr(b'=', &input[1..]).map(|p| p + 1);
        pos.map(|p| {
            (
                OsStringExt::from_vec(input[..p].to_vec()),
                OsStringExt::from_vec(input[p + 1..].to_vec()),
            )
        })
    }
}

pub fn getenv(k: &OsStr) -> Option<OsString> {
    // environment variables with a nul byte can't be set, so their value is
    // always None as well
    run_with_cstr(k.as_bytes(), &|k| {
        let _guard = env_read_lock();
        let v = unsafe { libc::getenv(k.as_ptr()) } as *const libc::c_char;

        if v.is_null() {
            Ok(None)
        } else {
            // SAFETY: `v` cannot be mutated while executing this line since we've a read lock
            let bytes = unsafe { CStr::from_ptr(v) }.to_bytes().to_vec();

            Ok(Some(OsStringExt::from_vec(bytes)))
        }
    })
    .ok()
    .flatten()
}

pub unsafe fn setenv(k: &OsStr, v: &OsStr) -> io::Result<()> {
    run_with_cstr(k.as_bytes(), &|k| {
        run_with_cstr(v.as_bytes(), &|v| unsafe {
            let _guard = env_write_lock();
            cvt(libc::setenv(k.as_ptr(), v.as_ptr(), 1)).map(drop)
        })
    })
}

pub unsafe fn unsetenv(n: &OsStr) -> io::Result<()> {
    run_with_cstr(n.as_bytes(), &|nbuf| unsafe {
        let _guard = env_write_lock();
        cvt(libc::unsetenv(nbuf.as_ptr())).map(drop)
    })
}

#[allow(dead_code)]
pub fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

pub fn temp_dir() -> PathBuf {
    crate::env::var_os("TMPDIR").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"))
}

pub fn home_dir() -> Option<PathBuf> {
    crate::env::var_os("HOME").filter(|s| !s.is_empty()).map(PathBuf::from)
}

pub fn exit(code: i32) -> ! {
    unsafe { libc::exit(code) }
}

/// getpid(2).
pub fn getpid() -> u32 {
    const SYS_GETPID: i32 = 172;
    super::linux::raw(SYS_GETPID, [0; 6]).unwrap_or(0) as u32
}

#[doc(hidden)]
pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() { Err(io::Error::last_os_error()) } else { Ok(t) }
}
