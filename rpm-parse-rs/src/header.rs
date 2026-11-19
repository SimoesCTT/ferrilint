use thiserror::Error;

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Invalid RPM header magic")]
    InvalidMagic,
    #[error("Malformed header index table")]
    MalformedIndex,
}

#[derive(Debug, Clone)]
pub struct HeaderIndex {
    pub tag: u32,
    pub data_type: u32,
    pub offset: u32,
    pub count: u32,
}

#[derive(Debug)]
pub struct RpmHeader {
    pub indexes: Vec<HeaderIndex>,
    pub store: Vec<u8>,
}

impl RpmHeader {
    pub const MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];

    pub fn parse(input: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        if input.len() < 16 || !input.starts_with(&Self::MAGIC) {
            return Err(HeaderError::InvalidMagic);
        }

        let index_count = u32::from_be_bytes([input[8], input[9], input[10], input[11]]) as usize;
        let store_size = u32::from_be_bytes([input[12], input[13], input[14], input[15]]) as usize;

        let header_len = 16 + (index_count * 16) + store_size;
        if input.len() < header_len {
            return Err(HeaderError::MalformedIndex);
        }

        let mut indexes = Vec::with_capacity(index_count);
        let mut ptr = 16;
        for _ in 0..index_count {
            let tag = u32::from_be_bytes(input[ptr..ptr+4].try_into().unwrap());
            let data_type = u32::from_be_bytes(input[ptr+4..ptr+8].try_into().unwrap());
            let offset = u32::from_be_bytes(input[ptr+8..ptr+12].try_into().unwrap());
            let count = u32::from_be_bytes(input[ptr+12..ptr+16].try_into().unwrap());
            indexes.push(HeaderIndex { tag, data_type, offset, count });
            ptr += 16;
        }

        let store_end = ptr + store_size;
        let store = input[ptr..store_end].to_vec();

        Ok((RpmHeader { indexes, store }, &input[header_len..]))
    }
}
