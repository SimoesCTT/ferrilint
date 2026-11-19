use thiserror::Error;

#[derive(Error, Debug)]
pub enum LeadError {
    #[error("Invalid magic bytes for RPM lead")]
    InvalidMagic,
    #[error("Buffer too short for RPM lead")]
    Truncated,
}

#[derive(Debug, Clone, Copy)]
pub struct RpmLead {
    pub magic: [u8; 4],
    pub major: u8,
    pub minor: u8,
    pub file_type: u16,
    pub arch_num: u16,
    pub name: [u8; 66],
    pub os_num: u16,
    pub signature_type: u16,
}

impl RpmLead {
    pub const MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];

    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), LeadError> {
        if input.len() < 96 {
            return Err(LeadError::Truncated);
        }
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&input[0..4]);
        if magic != Self::MAGIC {
            return Err(LeadError::InvalidMagic);
        }

        let major = input[4];
        let minor = input[5];
        let file_type = u16::from_be_bytes([input[6], input[7]]);
        let arch_num = u16::from_be_bytes([input[8], input[9]]);
        
        let mut name = [0u8; 66];
        name.copy_from_slice(&input[10..76]);
        
        let os_num = u16::from_be_bytes([input[76], input[77]]);
        let signature_type = u16::from_be_bytes([input[78], input[79]]);

        let lead = RpmLead {
            magic,
            major,
            minor,
            file_type,
            arch_num,
            name,
            os_num,
            signature_type,
        };

        Ok((lead, &input[96..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_lead_parse() {
        let mut mock_data = vec![0u8; 96];
        mock_data[0..4].copy_from_slice(&RpmLead::MAGIC);
        mock_data[4] = 3;
        mock_data[5] = 0;

        let (lead, remainder) = RpmLead::parse(&mock_data).unwrap();
        assert_eq!(lead.major, 3);
        assert_eq!(remainder.len(), 0);
    }
}
