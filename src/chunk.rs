use serde::Serialize;

use crate::config::ChunkingConfig;
use crate::content::DecodedContent;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChunkRecord {
    pub schema: &'static str,
    pub chunk_id: String,
    pub file_id: String,
    pub path: String,
    pub chunk_index: usize,
    pub content_hash: String,
    pub original_byte_start: usize,
    pub original_byte_end: usize,
    pub decoded_char_start: usize,
    pub decoded_char_end: usize,
    pub line_start: usize,
    pub line_end: usize,
    pub input_bytes: usize,
    #[serde(skip)]
    pub decoded_byte_start: usize,
    #[serde(skip)]
    pub decoded_byte_end: usize,
}

pub fn chunk_content(
    path: &str,
    content: &DecodedContent,
    config: &ChunkingConfig,
) -> Vec<ChunkRecord> {
    iter_chunks(path, content, config).collect()
}

/// Generate one record at a time so callers can enforce cancellation/deadlines.
pub fn iter_chunks<'a>(
    path: &'a str,
    content: &'a DecodedContent,
    config: &'a ChunkingConfig,
) -> impl Iterator<Item = ChunkRecord> + 'a {
    Chunks {
        path,
        content,
        config,
        file_id: hash(format!("{path}\0{}", hash(content.text.as_bytes())).as_bytes()),
        newline_offsets: content
            .text
            .match_indices('\n')
            .map(|(offset, _)| offset)
            .collect(),
        ranges: text_ranges(&content.text, config),
        index: 0,
    }
}

struct Chunks<'a> {
    path: &'a str,
    content: &'a DecodedContent,
    config: &'a ChunkingConfig,
    file_id: String,
    newline_offsets: Vec<usize>,
    ranges: TextRanges<'a>,
    index: usize,
}

impl Iterator for Chunks<'_> {
    type Item = ChunkRecord;

    fn next(&mut self) -> Option<Self::Item> {
        let range = self.ranges.next()?;
        let record = self.make_chunk(range.start, range.end);
        self.index += 1;
        Some(record)
    }
}

/// Exact UTF-8 chunk boundaries without file offset maps or per-character storage.
pub fn text_ranges<'a>(text: &'a str, config: &'a ChunkingConfig) -> TextRanges<'a> {
    TextRanges {
        text,
        config,
        next_start: Some(0),
    }
}

pub struct TextRanges<'a> {
    text: &'a str,
    config: &'a ChunkingConfig,
    next_start: Option<usize>,
}

impl Iterator for TextRanges<'_> {
    type Item = std::ops::Range<usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.next_start?;
        let text = self.text;
        let desired = start
            .saturating_add(self.config.target_bytes)
            .min(text.len());
        let mut end = floor_char_boundary(text, desired);
        if self.config.prefer_line_boundaries && end < text.len() {
            let search_start = floor_char_boundary(text, start + (end - start) / 2);
            if let Some(relative) = text[search_start..end].rfind('\n') {
                let candidate = search_start + relative + 1;
                if candidate > start {
                    end = candidate;
                }
            }
        }
        if end <= start {
            end = next_char_boundary(text, start);
        }
        self.next_start = if end == text.len() {
            None
        } else {
            let candidate =
                floor_char_boundary(text, end.saturating_sub(self.config.overlap_bytes));
            // UTF-8 rounding or a short line can make the requested overlap
            // reach the current start. Advance one character in that case.
            Some(if candidate > start {
                candidate
            } else {
                next_char_boundary(text, start)
            })
        };
        Some(start..end)
    }
}

impl Chunks<'_> {
    fn make_chunk(&self, start: usize, end: usize) -> ChunkRecord {
        let content_hash = hash(&self.content.text.as_bytes()[start..end]);
        let chunk_id = hash(
            format!(
                "{}\0{}\0{start}\0{end}\0{}\0{}\0{}",
                self.file_id,
                self.index,
                self.config.target_bytes,
                self.config.overlap_bytes,
                content_hash
            )
            .as_bytes(),
        );
        ChunkRecord {
            schema: "patronus.security-scanner.chunk.v1",
            chunk_id,
            file_id: self.file_id.clone(),
            path: self.path.into(),
            chunk_index: self.index,
            content_hash,
            original_byte_start: self.content.original_offset(start),
            original_byte_end: self.content.original_offset(end),
            decoded_char_start: self.content.char_index(start),
            decoded_char_end: self.content.char_index(end),
            line_start: 1 + self
                .newline_offsets
                .partition_point(|offset| *offset < start),
            line_end: 1 + self.newline_offsets.partition_point(|offset| *offset < end),
            input_bytes: self
                .content
                .original_offset(end)
                .saturating_sub(self.content.original_offset(start)),
            decoded_byte_start: start,
            decoded_byte_end: end,
        }
    }
}

fn next_char_boundary(text: &str, start: usize) -> usize {
    text[start..]
        .char_indices()
        .nth(1)
        .map(|(offset, _)| start + offset)
        .unwrap_or(text.len())
}

fn floor_char_boundary(text: &str, mut offset: usize) -> usize {
    while offset > 0 && !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

pub fn hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}
