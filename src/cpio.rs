#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpioError {
    TruncatedHeader,
    InvalidMagic,
    InvalidHexField,
    TruncatedPayload,
}

#[derive(Debug, Clone, Copy)]
pub struct CpioEntry<'a> {
    pub path: &'a str,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub data: &'a [u8],
}

impl<'a> CpioEntry<'a> {
    #[inline]
    pub fn is_dir(&self) -> bool {
        (self.mode & 0o170000) == 0o040000
    }

    #[inline]
    pub fn is_regular_file(&self) -> bool {
        (self.mode & 0o170000) == 0o100000
    }

    #[inline]
    pub fn is_symlink(&self) -> bool {
        (self.mode & 0o170000) == 0o120000
    }

    #[inline]
    pub fn permissions(&self) -> u32 {
        self.mode & 0o7777
    }
}

pub struct CpioReader<'a> {
    buf: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> CpioReader<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            offset: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for CpioReader<'a> {
    type Item = Result<CpioEntry<'a>, CpioError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.buf.len() {
            return None;
        }

        if self.offset + 110 > self.buf.len() {
            self.done = true;
            return Some(Err(CpioError::TruncatedHeader));
        }

        let hdr = &self.buf[self.offset..self.offset + 110];
        let magic = &hdr[0..6];
        if magic != b"070701" && magic != b"070702" {
            self.done = true;
            return Some(Err(CpioError::InvalidMagic));
        }

        let parse_hex = |range: std::ops::Range<usize>| -> Result<u32, CpioError> {
            let s = std::str::from_utf8(&hdr[range]).map_err(|_| CpioError::InvalidHexField)?;
            u32::from_str_radix(s, 16).map_err(|_| CpioError::InvalidHexField)
        };

        let mode = match parse_hex(14..22) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let uid = match parse_hex(22..30) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let gid = match parse_hex(30..38) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let nlink = match parse_hex(38..46) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let mtime = match parse_hex(46..54) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let filesize = match parse_hex(54..62) { Ok(v) => v as usize, Err(e) => { self.done = true; return Some(Err(e)); } };
        let dev_major = match parse_hex(62..70) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let dev_minor = match parse_hex(70..78) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let rdev_major = match parse_hex(78..86) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let rdev_minor = match parse_hex(86..94) { Ok(v) => v, Err(e) => { self.done = true; return Some(Err(e)); } };
        let namesize = match parse_hex(94..102) { Ok(v) => v as usize, Err(e) => { self.done = true; return Some(Err(e)); } };

        if namesize < 2 || self.offset + 110 + namesize > self.buf.len() {
            self.done = true;
            return Some(Err(CpioError::TruncatedPayload));
        }

        let name_start = self.offset + 110;
        let name_end = name_start + namesize;

        let raw_name = &self.buf[name_start..name_end - 1];
        let path_str = match std::str::from_utf8(raw_name) {
            Ok(s) => s,
            Err(_) => {
                self.done = true;
                return Some(Err(CpioError::InvalidHexField));
            }
        };

        if path_str == "TRAILER!!!" {
            self.done = true;
            return None;
        }

        let clean_path = path_str.strip_prefix('.').unwrap_or(path_str);

        let data_start = (name_end + 3) & !3;
        let data_end = data_start + filesize;
        if data_end > self.buf.len() {
            self.done = true;
            return Some(Err(CpioError::TruncatedPayload));
        }

        let data = &self.buf[data_start..data_end];
        self.offset = (data_end + 3) & !3;

        Some(Ok(CpioEntry {
            path: clean_path,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            dev_major,
            dev_minor,
            rdev_major,
            rdev_minor,
            data,
        }))
    }
}
