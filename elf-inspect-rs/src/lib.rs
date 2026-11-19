//! # elf-inspect-rs
//! Native ELF64 inspection and security hardening flag auditing engine.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ElfError {
    #[error("Not a valid ELF binary (missing 0x7fELF magic)")]
    InvalidMagic,
    #[error("Unsupported ELF class (only ELF64 supported)")]
    UnsupportedClass,
    #[error("Truncated ELF header or program headers")]
    Truncated,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SecurityFlags {
    pub pie: bool,
    pub relro: String, // "None", "Partial", "Full"
    pub stack_canary: bool,
    pub nx: bool,
}

pub struct ElfInspector;

impl ElfInspector {
    pub fn audit_bytes(data: &[u8]) -> Result<SecurityFlags, ElfError> {
        if data.len() < 64 || !data.starts_with(&[0x7f, b'E', b'L', b'F']) {
            return Err(ElfError::InvalidMagic);
        }

        // EI_CLASS (index 4): 2 = 64-bit
        if data[4] != 2 {
            return Err(ElfError::UnsupportedClass);
        }

        // e_type (offset 16, 2 bytes): ET_DYN (3) indicates PIE / Shared Object
        let e_type = u16::from_le_bytes([data[16], data[17]]);
        let pie = e_type == 3;

        // e_phoff (offset 32, 8 bytes): Program header table offset
        let phoff = u64::from_le_bytes([
            data[32], data[33], data[34], data[35],
            data[36], data[37], data[38], data[39],
        ]) as usize;

        // e_phentsize (offset 54, 2 bytes) & e_phnum (offset 56, 2 bytes)
        let phentsize = u16::from_le_bytes([data[54], data[55]]) as usize;
        let phnum = u16::from_le_bytes([data[56], data[57]]) as usize;

        let mut has_relro = false;
        let mut has_nx = true; // Default true unless PT_GNU_STACK is executable

        if phoff > 0 && phnum > 0 {
            let table_size = phnum * std::cmp::max(phentsize, 56);
            if data.len() < phoff + table_size {
                return Err(ElfError::Truncated);
            }

            for i in 0..phnum {
                let entry_offset = phoff + (i * std::cmp::max(phentsize, 56));
                if entry_offset + 56 > data.len() {
                    break;
                }

                let p_type = u32::from_le_bytes([
                    data[entry_offset],
                    data[entry_offset + 1],
                    data[entry_offset + 2],
                    data[entry_offset + 3],
                ]);

                let p_flags = u32::from_le_bytes([
                    data[entry_offset + 4],
                    data[entry_offset + 5],
                    data[entry_offset + 6],
                    data[entry_offset + 7],
                ]);

                // PT_GNU_RELRO = 0x6474e552
                if p_type == 0x6474e552 {
                    has_relro = true;
                }

                // PT_GNU_STACK = 0x6474e551
                if p_type == 0x6474e551 {
                    let is_executable = (p_flags & 1) != 0;
                    if is_executable {
                        has_nx = false;
                    }
                }
            }
        }

        let relro = if has_relro {
            "Full".to_string()
        } else {
            "None".to_string()
        };

        let stack_canary = data.windows(16).any(|w| w.starts_with(b"__stack_chk_fail"));

        Ok(SecurityFlags {
            pie,
            relro,
            stack_canary,
            nx: has_nx,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_elf_magic() {
        let bad_data = vec![0u8; 64];
        assert_eq!(ElfInspector::audit_bytes(&bad_data), Err(ElfError::InvalidMagic));
    }

    #[test]
    fn test_mock_elf64_audit() {
        let mut elf = vec![0u8; 256];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN (PIE)
        
        elf[32..40].copy_from_slice(&(64u64.to_le_bytes()));
        elf[54..56].copy_from_slice(&(56u16.to_le_bytes()));
        elf[56..58].copy_from_slice(&(2u16.to_le_bytes()));

        elf[64..68].copy_from_slice(&0x6474e552u32.to_le_bytes());

        let ph1_offset = 64 + 56;
        elf[ph1_offset..ph1_offset + 4].copy_from_slice(&0x6474e551u32.to_le_bytes());
        elf[ph1_offset + 4..ph1_offset + 8].copy_from_slice(&6u32.to_le_bytes());

        let flags = ElfInspector::audit_bytes(&elf).unwrap();
        assert!(flags.pie);
        assert_eq!(flags.relro, "Full");
        assert!(flags.nx);
    }
}
