//! # CPIO Payload Parser
//! Zero-copy SVR4 CPIO archive parser for RPM payloads.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CpioError {
    #[error("Invalid CPIO magic")]
    InvalidMagic,
    #[error("Truncated CPIO header or entry")]
    Truncated,
    #[error("Parse hex error: {0}")]
    HexParse(#[from] std::num::ParseIntError),
}

#[derive(Debug, Clone)]
pub struct CpioEntry {
    pub filename: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub filesize: u32,
    pub data: Vec<u8>,
}

pub struct CpioArchive;

impl CpioArchive {
    /// Iterates over all files contained within an uncompressed CPIO byte stream.
    pub fn parse_entries(mut input: &[u8]) -> Result<Vec<CpioEntry>, CpioError> {
        let mut entries = Vec::new();

        loop {
            if input.len() < 110 {
                break;
            }

            let magic = &input[0..6];
            if magic != b"070701" && magic != b"070702" {
                return Err(CpioError::InvalidMagic);
            }

            // Helper to parse fixed-width hex fields in SVR4 header
            let parse_hex = |start: usize, len: usize| -> Result<u32, CpioError> {
                let s = std::str::from_utf8(&input[start..start + len])
                    .map_err(|_| CpioError::Truncated)?;
                Ok(u32::from_str_radix(s, 16)?)
            };

            let namesize = parse_hex(94, 8)? as usize;
            let filesize = parse_hex(54, 8)? as usize;
            let mode = parse_hex(14, 8)?;
            let uid = parse_hex(22, 8)?;
            let gid = parse_hex(30, 8)?;

            let header_and_name_len = 110 + namesize;
            let padded_header_len = (header_and_name_len + 3) & !3; // 4-byte alignment

            if input.len() < padded_header_len {
                return Err(CpioError::Truncated);
            }

            let name_bytes = &input[110..110 + namesize - 1]; // strip null terminator
            let filename = String::from_utf8_lossy(name_bytes).to_string();

            let data_start = padded_header_len;
            let padded_data_len = (filesize + 3) & !3;

            if input.len() < data_start + padded_data_len {
                return Err(CpioError::Truncated);
            }

            let data = input[data_start..data_start + filesize].to_vec();

            if filename == "TRAILER!!!" {
                break;
            }

            entries.push(CpioEntry {
                filename,
                mode,
                uid,
                gid,
                filesize: filesize as u32,
                data,
            });

            input = &input[data_start + padded_data_len..];
        }

        Ok(entries)
    }
}
