#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelroStatus {
    None,
    Partial,
    Full,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfAudit {
    pub is_pie: bool,
    pub relro: RelroStatus,
    pub stack_executable: bool,
    pub has_nx: bool,
    pub has_rpath: bool,
    pub runpath: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    InvalidMagic,
    UnsupportedClass,
    TruncatedHeader,
    TruncatedProgramHeaders,
}

fn read_cstr(buf: &[u8], start: usize) -> Option<String> {
    if start >= buf.len() {
        return None;
    }
    let mut end = start;
    while end < buf.len() && buf[end] != 0 {
        end += 1;
    }
    std::str::from_utf8(&buf[start..end]).ok().map(|s| s.to_string())
}

pub fn audit_elf(buf: &[u8]) -> Result<ElfAudit, ElfError> {
    if buf.len() < 64 {
        return Err(ElfError::TruncatedHeader);
    }

    if &buf[0..4] != b"\x7fELF" {
        return Err(ElfError::InvalidMagic);
    }

    let class = buf[4];
    if class != 2 {
        return Err(ElfError::UnsupportedClass);
    }

    let e_type = u16::from_le_bytes([buf[16], buf[17]]);
    let is_pie = e_type == 3;

    let e_phoff = u64::from_le_bytes([
        buf[32], buf[33], buf[34], buf[35],
        buf[36], buf[37], buf[38], buf[39],
    ]) as usize;

    let e_phentsize = u16::from_le_bytes([buf[54], buf[55]]) as usize;
    let e_phnum = u16::from_le_bytes([buf[56], buf[57]]) as usize;

    let ph_end = e_phoff.saturating_add(e_phnum.saturating_mul(e_phentsize));
    if ph_end > buf.len() {
        return Err(ElfError::TruncatedProgramHeaders);
    }

    let mut has_relro = false;
    let mut has_bind_now = false;
    let mut stack_executable = false;
    let mut has_nx = false;
    let mut has_rpath = false;
    let mut runpath_val = None;
    let mut dyn_string_table_offset: Option<usize> = None;

    for i in 0..e_phnum {
        let entry_off = e_phoff + i * e_phentsize;
        if entry_off + 56 > buf.len() {
            break;
        }

        let p_type = u32::from_le_bytes([
            buf[entry_off], buf[entry_off + 1], buf[entry_off + 2], buf[entry_off + 3],
        ]);
        let p_flags = u32::from_le_bytes([
            buf[entry_off + 4], buf[entry_off + 5], buf[entry_off + 6], buf[entry_off + 7],
        ]);

        if p_type == 0x6474e552 {
            has_relro = true;
        }
        if p_type == 0x6474e551 {
            has_nx = (p_flags & 1) == 0;
            stack_executable = (p_flags & 1) != 0;
        }

        if p_type == 2 { // PT_DYNAMIC
            let p_offset = u64::from_le_bytes([
                buf[entry_off + 8], buf[entry_off + 9], buf[entry_off + 10], buf[entry_off + 11],
                buf[entry_off + 12], buf[entry_off + 13], buf[entry_off + 14], buf[entry_off + 15],
            ]) as usize;
            let p_filesz = u64::from_le_bytes([
                buf[entry_off + 32], buf[entry_off + 33], buf[entry_off + 34], buf[entry_off + 35],
                buf[entry_off + 36], buf[entry_off + 37], buf[entry_off + 38], buf[entry_off + 39],
            ]) as usize;

            let dyn_end = p_offset.saturating_add(p_filesz);
            if dyn_end <= buf.len() {
                let mut d_off = p_offset;
                while d_off + 16 <= dyn_end {
                    let d_tag = i64::from_le_bytes([
                        buf[d_off], buf[d_off + 1], buf[d_off + 2], buf[d_off + 3],
                        buf[d_off + 4], buf[d_off + 5], buf[d_off + 6], buf[d_off + 7],
                    ]);
                    let d_val = u64::from_le_bytes([
                        buf[d_off + 8], buf[d_off + 9], buf[d_off + 10], buf[d_off + 11],
                        buf[d_off + 12], buf[d_off + 13], buf[d_off + 14], buf[d_off + 15],
                    ]);

                    if d_tag == 0 { break; }
                    if d_tag == 5 { // DT_STRTAB
                        dyn_string_table_offset = Some(d_val as usize);
                    }
                    d_off += 16;
                }

                d_off = p_offset;
                while d_off + 16 <= dyn_end {
                    let d_tag = i64::from_le_bytes([
                        buf[d_off], buf[d_off + 1], buf[d_off + 2], buf[d_off + 3],
                        buf[d_off + 4], buf[d_off + 5], buf[d_off + 6], buf[d_off + 7],
                    ]);
                    let d_val = u64::from_le_bytes([
                        buf[d_off + 8], buf[d_off + 9], buf[d_off + 10], buf[d_off + 11],
                        buf[d_off + 12], buf[d_off + 13], buf[d_off + 14], buf[d_off + 15],
                    ]);

                    if d_tag == 0 { break; }
                    if d_tag == 25 && (d_val & 0x08) != 0 { has_bind_now = true; }
                    if d_tag == 32 && (d_val & 0x00000001) != 0 { has_bind_now = true; }

                    if d_tag == 15 { // DT_RPATH
                        has_rpath = true;
                    }
                    if d_tag == 29 { // DT_RUNPATH
                        if let Some(strtab) = dyn_string_table_offset {
                            runpath_val = read_cstr(buf, strtab + d_val as usize);
                        }
                    }
                    d_off += 16;
                }
            }
        }
    }

    let relro = match (has_relro, has_bind_now) {
        (true, true) => RelroStatus::Full,
        (true, false) => RelroStatus::Partial,
        (false, _) => RelroStatus::None,
    };

    Ok(ElfAudit {
        is_pie,
        relro,
        stack_executable,
        has_nx,
        has_rpath,
        runpath: runpath_val,
    })
}
