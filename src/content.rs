use std::path::Path;

use crate::error::{IoContext, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Encoding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Utf16Le => "utf-16le-bom",
            Self::Utf16Be => "utf-16be-bom",
        }
    }
}

#[derive(Debug)]
pub struct DecodedContent {
    pub text: String,
    pub encoding: Encoding,
    /// One entry per decoded character boundary: (UTF-8 byte offset, original byte offset).
    pub positions: Vec<(usize, usize)>,
    pub original_len: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ContentError {
    #[error("file changed size after discovery")]
    Changed,
    #[error("binary content")]
    Binary,
    #[error("unsupported or invalid text encoding")]
    Encoding,
    #[error("path resolved outside the selected scan root")]
    OutsideRoot,
}

pub fn read_decode(
    path: &Path,
    expected_size: u64,
    max_size: u64,
    scan_root: &Path,
) -> Result<std::result::Result<DecodedContent, ContentError>> {
    let metadata = std::fs::symlink_metadata(path).at(path)?;
    if !metadata.is_file() || metadata.len() != expected_size || metadata.len() > max_size {
        return Ok(Err(ContentError::Changed));
    }
    let canonical = std::fs::canonicalize(path).at(path)?;
    if !canonical.starts_with(scan_root) {
        return Ok(Err(ContentError::OutsideRoot));
    }
    let bytes = std::fs::read(path).at(path)?;
    if obvious_binary(&bytes) {
        return Ok(Err(ContentError::Binary));
    }
    Ok(decode(&bytes))
}

pub fn obvious_binary(bytes: &[u8]) -> bool {
    let prefix = &bytes[..bytes.len().min(8192)];
    if prefix.starts_with(&[0xff, 0xfe]) || prefix.starts_with(&[0xfe, 0xff]) {
        return false;
    }
    prefix.contains(&0)
        || (!prefix.is_empty()
            && prefix
                .iter()
                .filter(|byte| **byte < 0x09 || (**byte > 0x0d && **byte < 0x20))
                .count()
                * 10
                > prefix.len())
}

pub fn decode(bytes: &[u8]) -> std::result::Result<DecodedContent, ContentError> {
    if let Some(payload) = bytes.strip_prefix(&[0xff, 0xfe]) {
        decode_utf16(payload, true, bytes.len())
    } else if let Some(payload) = bytes.strip_prefix(&[0xfe, 0xff]) {
        decode_utf16(payload, false, bytes.len())
    } else {
        let payload = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        let bom = bytes.len() - payload.len();
        let text = std::str::from_utf8(payload)
            .map_err(|_| ContentError::Encoding)?
            .to_owned();
        let mut positions = text
            .char_indices()
            .map(|(offset, _)| (offset, offset + bom))
            .collect::<Vec<_>>();
        positions.push((text.len(), bytes.len()));
        Ok(DecodedContent {
            text,
            encoding: Encoding::Utf8,
            positions,
            original_len: bytes.len(),
        })
    }
}

fn decode_utf16(
    payload: &[u8],
    little: bool,
    original_len: usize,
) -> std::result::Result<DecodedContent, ContentError> {
    if payload.len() % 2 != 0 {
        return Err(ContentError::Encoding);
    }
    let units = payload
        .chunks_exact(2)
        .map(|pair| {
            if little {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    let mut text = String::new();
    let mut positions = Vec::new();
    let mut unit_index = 0usize;
    while unit_index < units.len() {
        positions.push((text.len(), 2 + unit_index * 2));
        let first = units[unit_index];
        let (code, consumed) = if (0xd800..=0xdbff).contains(&first) {
            let Some(second) = units.get(unit_index + 1).copied() else {
                return Err(ContentError::Encoding);
            };
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(ContentError::Encoding);
            }
            (
                0x10000 + (((first - 0xd800) as u32) << 10) + (second - 0xdc00) as u32,
                2,
            )
        } else if (0xdc00..=0xdfff).contains(&first) {
            return Err(ContentError::Encoding);
        } else {
            (first as u32, 1)
        };
        text.push(char::from_u32(code).ok_or(ContentError::Encoding)?);
        unit_index += consumed;
    }
    positions.push((text.len(), original_len));
    Ok(DecodedContent {
        text,
        encoding: if little {
            Encoding::Utf16Le
        } else {
            Encoding::Utf16Be
        },
        positions,
        original_len,
    })
}

impl DecodedContent {
    pub fn original_offset(&self, decoded_byte: usize) -> usize {
        self.positions
            .binary_search_by_key(&decoded_byte, |(offset, _)| *offset)
            .map(|index| self.positions[index].1)
            .unwrap_or_else(|index| self.positions[index.saturating_sub(1)].1)
    }

    pub fn char_index(&self, decoded_byte: usize) -> usize {
        self.positions
            .binary_search_by_key(&decoded_byte, |(offset, _)| *offset)
            .unwrap_or_else(|index| index)
    }
}
