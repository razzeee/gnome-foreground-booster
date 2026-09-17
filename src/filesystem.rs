//! Filesystem operations used by the policy and its test double.

use crate::cgroup::{DmemValue, write_dmem};
use std::fs::OpenOptions;
use std::io;
use std::path::Path;

pub(crate) trait PolicyIo {
    fn read(&self, path: &Path) -> io::Result<String>;
    fn write_dmem(&self, path: &Path, region: &str, value: DmemValue) -> io::Result<()>;
    fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Option<Vec<u8>>>;
    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> io::Result<()>;
    fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()>;
    fn xattrs_supported(&self, path: &Path) -> io::Result<()>;
    fn writable(&self, path: &Path) -> io::Result<()>;
}

pub(crate) struct RealIo;

impl PolicyIo for RealIo {
    fn read(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }

    fn write_dmem(&self, path: &Path, region: &str, value: DmemValue) -> io::Result<()> {
        write_dmem(path, region, value)
    }

    fn get_xattr(&self, path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
        xattr::get(path, name)
    }

    fn set_xattr(&self, path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
        xattr::set(path, name, value)
    }

    fn remove_xattr(&self, path: &Path, name: &str) -> io::Result<()> {
        xattr::remove(path, name)
    }

    fn xattrs_supported(&self, path: &Path) -> io::Result<()> {
        xattr::list(path).map(drop)
    }

    fn writable(&self, path: &Path) -> io::Result<()> {
        OpenOptions::new().write(true).open(path).map(drop)
    }
}
