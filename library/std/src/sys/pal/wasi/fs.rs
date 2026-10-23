#![forbid(unsafe_op_in_unsafe_fn)]

//! Filesystem operations.
//!
//! Paths are resolved by the kernel through the Linux system calls of BrowserOS (see `linux.rs`):
//! relative paths start at the kernel's working directory (`AT_FDCWD`), as on Linux. Reading,
//! writing and other operations on an open descriptor use WASI preview1, which shares the
//! descriptor table with the Linux entry. The WASI-specific extension traits that take a
//! directory descriptor (`std::os::wasi::fs`) keep using the preview1 path calls.

use super::fd::WasiFd;
use super::linux::{self, AT_FDCWD};
use crate::collections::VecDeque;
use crate::ffi::{CStr, OsStr, OsString};
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::os::wasi::ffi::{OsStrExt, OsStringExt};
use crate::os::wasi::io::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, RawFd};
use crate::path::{Path, PathBuf};
use crate::sync::Arc;
use crate::sys::common::small_c_string::run_path_with_cstr;
use crate::sys::time::SystemTime;
pub use crate::sys_common::fs::exists;
use crate::sys_common::{ignore_notfound, AsInner, FromInner, IntoInner};
use crate::{fmt, iter};

pub struct File {
    fd: WasiFd,
}

#[derive(Clone)]
pub struct FileAttr {
    meta: wasi::Filestat,
    mode: u32,
    /// Creation time, when the filesystem reports one (`STATX_BTIME`).
    btim: Option<wasi::Timestamp>,
}

pub struct ReadDir {
    inner: Arc<ReadDirInner>,
    buf: Vec<u8>,
    offset: usize,
    cap: usize,
    end: bool,
}

struct ReadDirInner {
    root: PathBuf,
    dir: File,
}

pub struct DirEntry {
    ino: wasi::Inode,
    d_type: u8,
    name: Vec<u8>,
    inner: Arc<ReadDirInner>,
}

#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    dirflags: wasi::Lookupflags,
    fdflags: wasi::Fdflags,
    oflags: wasi::Oflags,
    rights_base: Option<wasi::Rights>,
    rights_inheriting: Option<wasi::Rights>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FilePermissions {
    mode: u32,
}

#[derive(Copy, Clone, Debug, Default)]
pub struct FileTimes {
    accessed: Option<SystemTime>,
    modified: Option<SystemTime>,
}

#[derive(PartialEq, Eq, Hash, Debug, Copy, Clone)]
pub struct FileType {
    bits: wasi::Filetype,
}

#[derive(Debug)]
pub struct DirBuilder {}

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

    /// A `struct statx_timestamp` in nanoseconds since the epoch.
    fn timestamp(&self, offset: usize) -> wasi::Timestamp {
        let seconds = self.u64(offset) as i64;
        let nanoseconds = self.u32(offset + 8) as i64;
        seconds.saturating_mul(1_000_000_000).saturating_add(nanoseconds).max(0) as u64
    }

    fn attr(&self) -> FileAttr {
        let mode = self.u16(0x1c) as u32;
        let major = self.u32(0x88) as u64;
        let minor = self.u32(0x8c) as u64;
        FileAttr {
            meta: wasi::Filestat {
                // makedev(3)
                dev: ((major & 0xfffff000) << 32)
                    | ((major & 0xfff) << 8)
                    | ((minor & 0xffffff00) << 12)
                    | (minor & 0xff),
                ino: self.u64(0x20),
                filetype: filetype_of_mode(mode),
                nlink: self.u32(0x10) as u64,
                size: self.u64(0x28),
                atim: self.timestamp(0x40),
                mtim: self.timestamp(0x70),
                ctim: self.timestamp(0x60),
            },
            mode,
            btim: if self.u32(0) & linux::STATX_BTIME != 0 {
                Some(self.timestamp(0x50))
            } else {
                None
            },
        }
    }
}

fn filetype_of_mode(mode: u32) -> wasi::Filetype {
    match mode & linux::S_IFMT {
        linux::S_IFDIR => wasi::FILETYPE_DIRECTORY,
        linux::S_IFREG => wasi::FILETYPE_REGULAR_FILE,
        linux::S_IFLNK => wasi::FILETYPE_SYMBOLIC_LINK,
        linux::S_IFCHR => wasi::FILETYPE_CHARACTER_DEVICE,
        linux::S_IFBLK => wasi::FILETYPE_BLOCK_DEVICE,
        linux::S_IFSOCK => wasi::FILETYPE_SOCKET_STREAM,
        _ => wasi::FILETYPE_UNKNOWN,
    }
}

/// statx(2) of `path` relative to `dirfd`.
fn statx(dirfd: RawFd, path: &CStr, flags: i32) -> io::Result<FileAttr> {
    let mut buf = Statx([0; 256]);
    linux::call(
        linux::SYS_STATX,
        [
            dirfd as i64,
            linux::path(path),
            flags as i64,
            linux::STATX_BASIC_STATS as i64 | linux::STATX_BTIME as i64,
            linux::ptr(buf.0.as_mut_ptr()),
            0,
        ],
    )?;
    Ok(buf.attr())
}

/// openat(2). The new descriptor is close-on-exec, as std opens everything on Linux.
fn openat(dirfd: RawFd, path: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    let fd = linux::call(
        linux::SYS_OPENAT,
        [dirfd as i64, linux::path(path), (flags | linux::O_CLOEXEC) as i64, mode as i64, 0, 0],
    )?;
    // SAFETY: the kernel has just given us this descriptor.
    Ok(File { fd: unsafe { WasiFd::from_raw_fd(fd as RawFd) } })
}

fn unlinkat(dirfd: RawFd, path: &CStr, flags: i32) -> io::Result<()> {
    linux::call(linux::SYS_UNLINKAT, [dirfd as i64, linux::path(path), flags as i64, 0, 0, 0])
        .map(drop)
}

impl FileAttr {
    pub fn size(&self) -> u64 {
        self.meta.size
    }

    pub fn perm(&self) -> FilePermissions {
        FilePermissions { mode: self.mode & 0o7777 }
    }

    pub fn file_type(&self) -> FileType {
        FileType { bits: self.meta.filetype }
    }

    pub fn modified(&self) -> io::Result<SystemTime> {
        Ok(SystemTime::from_wasi_timestamp(self.meta.mtim))
    }

    pub fn accessed(&self) -> io::Result<SystemTime> {
        Ok(SystemTime::from_wasi_timestamp(self.meta.atim))
    }

    pub fn created(&self) -> io::Result<SystemTime> {
        match self.btim {
            Some(btim) => Ok(SystemTime::from_wasi_timestamp(btim)),
            None => Err(io::const_io_error!(
                io::ErrorKind::Unsupported,
                "creation time is not available for the filesystem",
            )),
        }
    }

    pub(crate) fn as_wasi(&self) -> &wasi::Filestat {
        &self.meta
    }
}

impl FilePermissions {
    pub fn readonly(&self) -> bool {
        // check if any class (owner, group, others) has write permission
        self.mode & 0o222 == 0
    }

    pub fn set_readonly(&mut self, readonly: bool) {
        if readonly {
            // remove write permission for all classes; equivalent to `chmod a-w <file>`
            self.mode &= !0o222;
        } else {
            // add write permission for all classes; equivalent to `chmod a+w <file>`
            self.mode |= 0o222;
        }
    }
}

impl FileTimes {
    pub fn set_accessed(&mut self, t: SystemTime) {
        self.accessed = Some(t);
    }

    pub fn set_modified(&mut self, t: SystemTime) {
        self.modified = Some(t);
    }
}

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.bits == wasi::FILETYPE_DIRECTORY
    }

    pub fn is_file(&self) -> bool {
        self.bits == wasi::FILETYPE_REGULAR_FILE
    }

    pub fn is_symlink(&self) -> bool {
        self.bits == wasi::FILETYPE_SYMBOLIC_LINK
    }

    pub(crate) fn bits(&self) -> wasi::Filetype {
        self.bits
    }
}

impl ReadDir {
    fn new(dir: File, root: PathBuf) -> ReadDir {
        ReadDir {
            inner: Arc::new(ReadDirInner { dir, root }),
            buf: vec![0; 4096],
            offset: 0,
            cap: 0,
            end: false,
        }
    }
}

impl fmt::Debug for ReadDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadDir").field(&"root", &self.inner.root).finish_non_exhaustive()
    }
}

impl Iterator for ReadDir {
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<io::Result<DirEntry>> {
        loop {
            if self.offset >= self.cap {
                if self.end {
                    return None;
                }
                // getdents64(2) fills the buffer with whole `struct linux_dirent64` records.
                let read = linux::call(
                    linux::SYS_GETDENTS64,
                    [
                        self.inner.dir.fd.as_raw_fd() as i64,
                        linux::ptr(self.buf.as_mut_ptr()),
                        self.buf.len() as i64,
                        0,
                        0,
                        0,
                    ],
                );
                match read {
                    Ok(0) => {
                        self.end = true;
                        return None;
                    }
                    Ok(bytes) => {
                        self.cap = bytes as usize;
                        self.offset = 0;
                    }
                    Err(e) => {
                        self.end = true;
                        return Some(Err(e));
                    }
                }
            }

            // struct linux_dirent64 { u64 d_ino; s64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }
            let record = &self.buf[self.offset..self.cap];
            let ino = u64::from_le_bytes(record[0..8].try_into().unwrap());
            let reclen = u16::from_le_bytes([record[16], record[17]]) as usize;
            let d_type = record[18];
            let name = &record[19..reclen];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            self.offset += reclen;

            // These names are skipped on all other platforms, so let's skip
            // them here too
            if name == b"." || name == b".." {
                continue;
            }

            return Some(Ok(DirEntry {
                ino,
                d_type,
                name: name.to_vec(),
                inner: self.inner.clone(),
            }));
        }
    }
}

impl DirEntry {
    pub fn path(&self) -> PathBuf {
        let name = OsStr::from_bytes(&self.name);
        self.inner.root.join(name)
    }

    pub fn file_name(&self) -> OsString {
        OsString::from_vec(self.name.clone())
    }

    pub fn metadata(&self) -> io::Result<FileAttr> {
        run_path_with_cstr(OsStr::from_bytes(&self.name).as_ref(), &|name| {
            statx(self.inner.dir.fd.as_raw_fd(), name, linux::AT_SYMLINK_NOFOLLOW)
        })
    }

    pub fn file_type(&self) -> io::Result<FileType> {
        let bits = match self.d_type {
            linux::DT_DIR => wasi::FILETYPE_DIRECTORY,
            linux::DT_REG => wasi::FILETYPE_REGULAR_FILE,
            linux::DT_LNK => wasi::FILETYPE_SYMBOLIC_LINK,
            linux::DT_CHR => wasi::FILETYPE_CHARACTER_DEVICE,
            linux::DT_BLK => wasi::FILETYPE_BLOCK_DEVICE,
            linux::DT_SOCK => wasi::FILETYPE_SOCKET_STREAM,
            linux::DT_UNKNOWN => return self.metadata().map(|m| m.file_type()),
            _ => wasi::FILETYPE_UNKNOWN,
        };
        Ok(FileType { bits })
    }

    pub fn ino(&self) -> wasi::Inode {
        self.ino
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        let mut base = OpenOptions::default();
        base.dirflags = wasi::LOOKUPFLAGS_SYMLINK_FOLLOW;
        base
    }

    pub fn read(&mut self, read: bool) {
        self.read = read;
    }

    pub fn write(&mut self, write: bool) {
        self.write = write;
    }

    pub fn truncate(&mut self, truncate: bool) {
        self.oflag(wasi::OFLAGS_TRUNC, truncate);
    }

    pub fn create(&mut self, create: bool) {
        self.oflag(wasi::OFLAGS_CREAT, create);
    }

    pub fn create_new(&mut self, create_new: bool) {
        self.oflag(wasi::OFLAGS_EXCL, create_new);
        self.oflag(wasi::OFLAGS_CREAT, create_new);
    }

    pub fn directory(&mut self, directory: bool) {
        self.oflag(wasi::OFLAGS_DIRECTORY, directory);
    }

    fn oflag(&mut self, bit: wasi::Oflags, set: bool) {
        if set {
            self.oflags |= bit;
        } else {
            self.oflags &= !bit;
        }
    }

    pub fn append(&mut self, append: bool) {
        self.append = append;
        self.fdflag(wasi::FDFLAGS_APPEND, append);
    }

    pub fn dsync(&mut self, set: bool) {
        self.fdflag(wasi::FDFLAGS_DSYNC, set);
    }

    pub fn nonblock(&mut self, set: bool) {
        self.fdflag(wasi::FDFLAGS_NONBLOCK, set);
    }

    pub fn rsync(&mut self, set: bool) {
        self.fdflag(wasi::FDFLAGS_RSYNC, set);
    }

    pub fn sync(&mut self, set: bool) {
        self.fdflag(wasi::FDFLAGS_SYNC, set);
    }

    fn fdflag(&mut self, bit: wasi::Fdflags, set: bool) {
        if set {
            self.fdflags |= bit;
        } else {
            self.fdflags &= !bit;
        }
    }

    pub fn fs_rights_base(&mut self, rights: wasi::Rights) {
        self.rights_base = Some(rights);
    }

    pub fn fs_rights_inheriting(&mut self, rights: wasi::Rights) {
        self.rights_inheriting = Some(rights);
    }

    fn rights_base(&self) -> wasi::Rights {
        if let Some(rights) = self.rights_base {
            return rights;
        }

        // If rights haven't otherwise been specified try to pick a reasonable
        // set. This can always be overridden by users via extension traits, and
        // implementations may give us fewer rights silently than we ask for. So
        // given that, just look at `read` and `write` and bucket permissions
        // based on that.
        let mut base = 0;
        if self.read {
            base |= wasi::RIGHTS_FD_READ;
            base |= wasi::RIGHTS_FD_READDIR;
        }
        if self.write || self.append {
            base |= wasi::RIGHTS_FD_WRITE;
            base |= wasi::RIGHTS_FD_DATASYNC;
            base |= wasi::RIGHTS_FD_ALLOCATE;
            base |= wasi::RIGHTS_FD_FILESTAT_SET_SIZE;
        }

        // FIXME: some of these should probably be read-only or write-only...
        base |= wasi::RIGHTS_FD_ADVISE;
        base |= wasi::RIGHTS_FD_FDSTAT_SET_FLAGS;
        base |= wasi::RIGHTS_FD_FILESTAT_GET;
        base |= wasi::RIGHTS_FD_FILESTAT_SET_TIMES;
        base |= wasi::RIGHTS_FD_SEEK;
        base |= wasi::RIGHTS_FD_SYNC;
        base |= wasi::RIGHTS_FD_TELL;
        base |= wasi::RIGHTS_PATH_CREATE_DIRECTORY;
        base |= wasi::RIGHTS_PATH_CREATE_FILE;
        base |= wasi::RIGHTS_PATH_FILESTAT_GET;
        base |= wasi::RIGHTS_PATH_LINK_SOURCE;
        base |= wasi::RIGHTS_PATH_LINK_TARGET;
        base |= wasi::RIGHTS_PATH_OPEN;
        base |= wasi::RIGHTS_PATH_READLINK;
        base |= wasi::RIGHTS_PATH_REMOVE_DIRECTORY;
        base |= wasi::RIGHTS_PATH_RENAME_SOURCE;
        base |= wasi::RIGHTS_PATH_RENAME_TARGET;
        base |= wasi::RIGHTS_PATH_SYMLINK;
        base |= wasi::RIGHTS_PATH_UNLINK_FILE;
        base |= wasi::RIGHTS_POLL_FD_READWRITE;

        base
    }

    fn rights_inheriting(&self) -> wasi::Rights {
        self.rights_inheriting.unwrap_or_else(|| self.rights_base())
    }

    pub fn lookup_flags(&mut self, flags: wasi::Lookupflags) {
        self.dirflags = flags;
    }

    /// The flags of open(2), checked the same way std does on Linux.
    fn linux_flags(&self) -> io::Result<i32> {
        let create = self.oflags & wasi::OFLAGS_CREAT != 0;
        let create_new = self.oflags & wasi::OFLAGS_EXCL != 0;
        let truncate = self.oflags & wasi::OFLAGS_TRUNC != 0;

        let access = match (self.read, self.write, self.append) {
            (true, false, false) => linux::O_RDONLY,
            (false, true, false) => linux::O_WRONLY,
            (true, true, false) => linux::O_RDWR,
            (false, _, true) => linux::O_WRONLY | linux::O_APPEND,
            (true, _, true) => linux::O_RDWR | linux::O_APPEND,
            (false, false, false) => return Err(linux::error(22)),
        };
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if truncate || create || create_new {
                    return Err(linux::error(22));
                }
            }
            (_, true) => {
                if truncate && !create_new {
                    return Err(linux::error(22));
                }
            }
        }
        let creation = match (create, truncate, create_new) {
            (false, false, false) => 0,
            (true, false, false) => linux::O_CREAT,
            (false, true, false) => linux::O_TRUNC,
            (true, true, false) => linux::O_CREAT | linux::O_TRUNC,
            (_, _, true) => linux::O_CREAT | linux::O_EXCL,
        };

        let mut flags = access | creation;
        if self.oflags & wasi::OFLAGS_DIRECTORY != 0 {
            flags |= linux::O_DIRECTORY;
        }
        if self.dirflags & wasi::LOOKUPFLAGS_SYMLINK_FOLLOW == 0 {
            flags |= linux::O_NOFOLLOW;
        }
        if self.fdflags & wasi::FDFLAGS_NONBLOCK != 0 {
            flags |= linux::O_NONBLOCK;
        }
        if self.fdflags & wasi::FDFLAGS_DSYNC != 0 {
            flags |= linux::O_DSYNC;
        }
        if self.fdflags & (wasi::FDFLAGS_SYNC | wasi::FDFLAGS_RSYNC) != 0 {
            flags |= linux::O_SYNC;
        }
        Ok(flags)
    }
}

impl File {
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File> {
        let flags = opts.linux_flags()?;
        run_path_with_cstr(path, &|path| openat(AT_FDCWD, path, flags, 0o666))
    }

    pub fn open_at(&self, path: &Path, opts: &OpenOptions) -> io::Result<File> {
        open_at(&self.fd, path, opts)
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> {
        statx(self.fd.as_raw_fd(), c"", linux::AT_EMPTY_PATH)
    }

    pub fn metadata_at(&self, flags: wasi::Lookupflags, path: &Path) -> io::Result<FileAttr> {
        metadata_at(&self.fd, flags, path)
    }

    pub fn fsync(&self) -> io::Result<()> {
        self.fd.sync()
    }

    pub fn datasync(&self) -> io::Result<()> {
        self.fd.datasync()
    }

    pub fn truncate(&self, size: u64) -> io::Result<()> {
        self.fd.filestat_set_size(size)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_vectored(&mut [IoSliceMut::new(buf)])
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.fd.read(bufs)
    }

    #[inline]
    pub fn is_read_vectored(&self) -> bool {
        true
    }

    pub fn read_buf(&self, cursor: BorrowedCursor<'_>) -> io::Result<()> {
        self.fd.read_buf(cursor)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.write_vectored(&[IoSlice::new(buf)])
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.fd.write(bufs)
    }

    #[inline]
    pub fn is_write_vectored(&self) -> bool {
        true
    }

    pub fn flush(&self) -> io::Result<()> {
        Ok(())
    }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64> {
        self.fd.seek(pos)
    }

    pub fn duplicate(&self) -> io::Result<File> {
        let fd = linux::call(
            linux::SYS_FCNTL64,
            [self.fd.as_raw_fd() as i64, linux::F_DUPFD_CLOEXEC as i64, 3, 0, 0, 0],
        )?;
        // SAFETY: the kernel has just given us this descriptor.
        Ok(File { fd: unsafe { WasiFd::from_raw_fd(fd as RawFd) } })
    }

    pub fn set_permissions(&self, perm: FilePermissions) -> io::Result<()> {
        linux::call(linux::SYS_FCHMOD, [self.fd.as_raw_fd() as i64, perm.mode as i64, 0, 0, 0, 0])
            .map(drop)
    }

    pub fn set_times(&self, times: FileTimes) -> io::Result<()> {
        let to_timestamp = |time: Option<SystemTime>| match time {
            Some(time) if let Some(ts) = time.to_wasi_timestamp() => Ok(ts),
            Some(_) => Err(io::const_io_error!(
                io::ErrorKind::InvalidInput,
                "timestamp is too large to set as a file time"
            )),
            None => Ok(0),
        };
        self.fd.filestat_set_times(
            to_timestamp(times.accessed)?,
            to_timestamp(times.modified)?,
            times.accessed.map_or(0, |_| wasi::FSTFLAGS_ATIM)
                | times.modified.map_or(0, |_| wasi::FSTFLAGS_MTIM),
        )
    }

    pub fn read_link(&self, file: &Path) -> io::Result<PathBuf> {
        read_link(&self.fd, file)
    }
}

impl AsInner<WasiFd> for File {
    #[inline]
    fn as_inner(&self) -> &WasiFd {
        &self.fd
    }
}

impl IntoInner<WasiFd> for File {
    fn into_inner(self) -> WasiFd {
        self.fd
    }
}

impl FromInner<WasiFd> for File {
    fn from_inner(fd: WasiFd) -> File {
        File { fd }
    }
}

impl AsFd for File {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for File {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for File {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

impl FromRawFd for File {
    unsafe fn from_raw_fd(raw_fd: RawFd) -> Self {
        unsafe { Self { fd: FromRawFd::from_raw_fd(raw_fd) } }
    }
}

impl DirBuilder {
    pub fn new() -> DirBuilder {
        DirBuilder {}
    }

    pub fn mkdir(&self, p: &Path) -> io::Result<()> {
        run_path_with_cstr(p, &|p| {
            linux::call(linux::SYS_MKDIRAT, [AT_FDCWD as i64, linux::path(p), 0o777, 0, 0, 0])
                .map(drop)
        })
    }
}

impl fmt::Debug for File {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("File").field("fd", &self.as_raw_fd()).finish()
    }
}

pub fn readdir(p: &Path) -> io::Result<ReadDir> {
    let dir = run_path_with_cstr(p, &|p| {
        openat(AT_FDCWD, p, linux::O_RDONLY | linux::O_DIRECTORY, 0)
    })?;
    Ok(ReadDir::new(dir, p.to_path_buf()))
}

pub fn unlink(p: &Path) -> io::Result<()> {
    run_path_with_cstr(p, &|p| unlinkat(AT_FDCWD, p, 0))
}

pub fn rename(old: &Path, new: &Path) -> io::Result<()> {
    run_path_with_cstr(old, &|old| {
        run_path_with_cstr(new, &|new| {
            linux::call(
                linux::SYS_RENAMEAT2,
                [AT_FDCWD as i64, linux::path(old), AT_FDCWD as i64, linux::path(new), 0, 0],
            )
            .map(drop)
        })
    })
}

pub fn set_perm(p: &Path, perm: FilePermissions) -> io::Result<()> {
    run_path_with_cstr(p, &|p| {
        linux::call(
            linux::SYS_FCHMODAT,
            [AT_FDCWD as i64, linux::path(p), perm.mode as i64, 0, 0, 0],
        )
        .map(drop)
    })
}

pub fn rmdir(p: &Path) -> io::Result<()> {
    run_path_with_cstr(p, &|p| unlinkat(AT_FDCWD, p, linux::AT_REMOVEDIR))
}

pub fn readlink(p: &Path) -> io::Result<PathBuf> {
    run_path_with_cstr(p, &|p| {
        let mut buf = Vec::with_capacity(256);
        loop {
            let len = linux::call(
                linux::SYS_READLINKAT,
                [
                    AT_FDCWD as i64,
                    linux::path(p),
                    linux::ptr(buf.as_mut_ptr()),
                    buf.capacity() as i64,
                    0,
                    0,
                ],
            )? as usize;
            // SAFETY: readlinkat(2) has written `len` bytes.
            unsafe { buf.set_len(len) };
            if len != buf.capacity() {
                buf.shrink_to_fit();
                return Ok(PathBuf::from(OsString::from_vec(buf)));
            }
            // Trigger the internal buffer resizing logic of `Vec` by requiring
            // more space than the current capacity. The length is guaranteed to be
            // the same as the capacity due to the if statement above.
            buf.reserve(1);
        }
    })
}

fn read_link(fd: &WasiFd, file: &Path) -> io::Result<PathBuf> {
    // Try to get a best effort initial capacity for the vector we're going to
    // fill. Note that if it's not a symlink we don't use a file to avoid
    // allocating gigabytes if you read_link a huge movie file by accident.
    // Additionally we add 1 to the initial size so if it doesn't change until
    // when we call `readlink` the returned length will be less than the
    // capacity, guaranteeing that we got all the data.
    let meta = metadata_at(fd, 0, file)?;
    let initial_size = if meta.file_type().is_symlink() {
        (meta.size() as usize).saturating_add(1)
    } else {
        1 // this'll fail in just a moment
    };

    // Now that we have an initial guess of how big to make our buffer, call
    // `readlink` in a loop until it fails or reports it filled fewer bytes than
    // we asked for, indicating we got everything.
    let file = osstr2str(file.as_ref())?;
    let mut destination = vec![0u8; initial_size];
    loop {
        let len = fd.readlink(file, &mut destination)?;
        if len < destination.len() {
            destination.truncate(len);
            destination.shrink_to_fit();
            return Ok(PathBuf::from(OsString::from_vec(destination)));
        }
        let amt_to_add = destination.len();
        destination.extend(iter::repeat(0).take(amt_to_add));
    }
}

pub fn symlink(original: &Path, link: &Path) -> io::Result<()> {
    run_path_with_cstr(original, &|original| {
        run_path_with_cstr(link, &|link| {
            linux::call(
                linux::SYS_SYMLINKAT,
                [linux::path(original), AT_FDCWD as i64, linux::path(link), 0, 0, 0],
            )
            .map(drop)
        })
    })
}

pub fn link(original: &Path, link: &Path) -> io::Result<()> {
    run_path_with_cstr(original, &|original| {
        run_path_with_cstr(link, &|link| {
            // Pass 0 as the flags argument, meaning don't follow symlinks.
            linux::call(
                linux::SYS_LINKAT,
                [AT_FDCWD as i64, linux::path(original), AT_FDCWD as i64, linux::path(link), 0, 0],
            )
            .map(drop)
        })
    })
}

pub fn stat(p: &Path) -> io::Result<FileAttr> {
    run_path_with_cstr(p, &|p| statx(AT_FDCWD, p, 0))
}

pub fn lstat(p: &Path) -> io::Result<FileAttr> {
    run_path_with_cstr(p, &|p| statx(AT_FDCWD, p, linux::AT_SYMLINK_NOFOLLOW))
}

fn metadata_at(fd: &WasiFd, flags: wasi::Lookupflags, path: &Path) -> io::Result<FileAttr> {
    let nofollow =
        if flags & wasi::LOOKUPFLAGS_SYMLINK_FOLLOW == 0 { linux::AT_SYMLINK_NOFOLLOW } else { 0 };
    run_path_with_cstr(path, &|path| statx(fd.as_raw_fd(), path, nofollow))
}

/// realpath(3), resolved the way musl does it: walk the components from the root (or the
/// working directory), following symbolic links, with at most 40 of them (ELOOP).
pub fn canonicalize(p: &Path) -> io::Result<PathBuf> {
    const MAX_LINKS: usize = 40;

    let bytes = p.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(linux::error(2));
    }
    let mut resolved: Vec<Vec<u8>> = Vec::new();
    let mut pending: VecDeque<Vec<u8>> = VecDeque::new();
    if bytes[0] != b'/' {
        let cwd = super::os::getcwd()?;
        pending.extend(split(cwd.as_os_str().as_bytes()));
    }
    pending.extend(split(bytes));

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
        let candidate = PathBuf::from(OsString::from_vec(candidate));
        if !lstat(&candidate)?.file_type().is_symlink() {
            resolved.push(name);
            continue;
        }
        links += 1;
        if links > MAX_LINKS {
            return Err(linux::error(40));
        }
        let target = readlink(&candidate)?;
        let target = target.as_os_str().as_bytes();
        if target.first() == Some(&b'/') {
            resolved.clear();
        }
        for component in split(target).into_iter().rev() {
            pending.push_front(component);
        }
    }

    let path = PathBuf::from(OsString::from_vec(join(&resolved)));
    // realpath(3) fails when the result does not exist; the walk above has checked every component.
    Ok(path)
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

fn open_at(fd: &WasiFd, path: &Path, opts: &OpenOptions) -> io::Result<File> {
    let fd = fd.open(
        opts.dirflags,
        osstr2str(path.as_ref())?,
        opts.oflags,
        opts.rights_base(),
        opts.rights_inheriting(),
        opts.fdflags,
    )?;
    Ok(File { fd })
}

pub fn osstr2str(f: &OsStr) -> io::Result<&str> {
    f.to_str()
        .ok_or_else(|| io::const_io_error!(io::ErrorKind::Uncategorized, "input must be utf-8"))
}

pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
    use crate::fs::{File, OpenOptions};

    let mut reader = File::open(from)?;
    let metadata = reader.metadata()?;
    if !metadata.is_file() {
        return Err(io::const_io_error!(
            io::ErrorKind::InvalidInput,
            "the source path is neither a regular file nor a symlink to a regular file",
        ));
    }
    let perm = metadata.permissions();

    let mut writer = OpenOptions::new().write(true).create(true).truncate(true).open(to)?;
    let written = io::copy(&mut reader, &mut writer)?;
    writer.set_permissions(perm)?;
    Ok(written)
}

pub fn remove_dir_all(path: &Path) -> io::Result<()> {
    // Removing a symbolic link removes the link, not the directory it points to.
    if lstat(path)?.file_type().is_symlink() {
        return unlink(path);
    }
    run_path_with_cstr(path, &|path| remove_dir_all_recursive(AT_FDCWD, path))
}

fn remove_dir_all_recursive(parent: RawFd, path: &CStr) -> io::Result<()> {
    // Open the directory without following a symbolic link, so a link that replaced the
    // directory is removed rather than followed.
    let dir = match openat(parent, path, linux::O_RDONLY | linux::O_DIRECTORY | linux::O_NOFOLLOW, 0)
    {
        Ok(dir) => dir,
        Err(err) if err.raw_os_error() == Some(wasi::ERRNO_NOTDIR.raw().into())
            || err.raw_os_error() == Some(wasi::ERRNO_LOOP.raw().into()) =>
        {
            return ignore_notfound(unlinkat(parent, path, 0));
        }
        Err(err) => return ignore_notfound(Err::<(), _>(err)),
    };
    let dirfd = dir.as_raw_fd();

    // this "root" is only used by `DirEntry::path` which we don't use below so
    // it's ok for this to be a bogus value
    for entry in ReadDir::new(dir, PathBuf::new()) {
        let entry = entry?;
        let result: io::Result<()> = run_path_with_cstr(OsStr::from_bytes(&entry.name).as_ref(), &|name| {
            if entry.file_type()?.is_dir() {
                remove_dir_all_recursive(dirfd, name)
            } else {
                unlinkat(dirfd, name, 0)
            }
        });
        // ignore internal NotFound errors
        if let Err(err) = &result
            && err.kind() != io::ErrorKind::NotFound
        {
            return result;
        }
    }

    // Once all this directory's contents are deleted it should be safe to
    // delete the directory itself.
    ignore_notfound(unlinkat(parent, path, linux::AT_REMOVEDIR))
}
