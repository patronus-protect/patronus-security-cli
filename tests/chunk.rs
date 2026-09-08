use patronus_security_scanner::chunk::{chunk_content, iter_chunks};
use patronus_security_scanner::config::ChunkingConfig;
use patronus_security_scanner::content::decode;

#[test]
fn chunks_unicode_without_empty_or_nonadvancing_ranges() {
    let content = decode("alpha\nβeta\n😀 gamma\ndelta".as_bytes()).unwrap();
    let config = ChunkingConfig {
        target_bytes: 12,
        overlap_bytes: 3,
        prefer_line_boundaries: true,
    };
    let chunks = chunk_content("src/example.rs", &content, &config);
    assert!(chunks.len() > 1);
    for chunk in &chunks {
        assert!(chunk.decoded_byte_end > chunk.decoded_byte_start);
        assert!(content.text.is_char_boundary(chunk.decoded_byte_start));
        assert!(content.text.is_char_boundary(chunk.decoded_byte_end));
    }
    assert_eq!(chunks, chunk_content("src/example.rs", &content, &config));
}

#[test]
fn empty_file_has_one_mappable_chunk() {
    let content = decode(b"").unwrap();
    let config = ChunkingConfig {
        target_bytes: 10,
        overlap_bytes: 2,
        prefer_line_boundaries: true,
    };
    let chunks = chunk_content("empty", &content, &config);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].original_byte_start, 0);
    assert_eq!(chunks[0].original_byte_end, 0);
}

#[test]
fn chunk_records_keep_stable_wire_contract() {
    let text = "alpha\nβeta\n😀 gamma\ndelta";
    let bytes: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let content = decode(&bytes).unwrap();
    let config = ChunkingConfig {
        target_bytes: 12,
        overlap_bytes: 3,
        prefer_line_boundaries: true,
    };
    let chunks = chunk_content("unicode.txt", &content, &config);
    // Captured from the existing eager implementation before the iterator change.
    let expected = serde_json::json!([
        {
            "schema": "patronus.security-scanner.chunk.v1",
            "chunk_id": "blake3:8d03ebe9843ef75117787e8d93bd28f019ad08757df797c1cc56ed9cfaafdb2d",
            "file_id": "blake3:85b8e3157c850a3310b4f031f9c955250fc8577fe34071e64d2eb507559a5952",
            "path": "unicode.txt", "chunk_index": 0,
            "content_hash": "blake3:68245ed6b5484feb47071e7e06e55c3dd12d7782a4add458d810ba158901d3c9",
            "original_byte_start": 2, "original_byte_end": 24,
            "decoded_char_start": 0, "decoded_char_end": 11,
            "line_start": 1, "line_end": 3, "input_bytes": 22
        },
        {
            "schema": "patronus.security-scanner.chunk.v1",
            "chunk_id": "blake3:d87894209b56768d6356a6e293292178b8fdfe2167865a108ffdd1adabf60cd8",
            "file_id": "blake3:85b8e3157c850a3310b4f031f9c955250fc8577fe34071e64d2eb507559a5952",
            "path": "unicode.txt", "chunk_index": 1,
            "content_hash": "blake3:0bf6f52a7a0b05b62a6af0ba9ae9e82e5d613db3da69b26c11cfaf06d3605443",
            "original_byte_start": 18, "original_byte_end": 38,
            "decoded_char_start": 8, "decoded_char_end": 17,
            "line_start": 2, "line_end": 3, "input_bytes": 20
        },
        {
            "schema": "patronus.security-scanner.chunk.v1",
            "chunk_id": "blake3:891068a6329656d05252876442bc0e3b7d3eba8d1ab69a3530a5fe10cb4c2e2d",
            "file_id": "blake3:85b8e3157c850a3310b4f031f9c955250fc8577fe34071e64d2eb507559a5952",
            "path": "unicode.txt", "chunk_index": 2,
            "content_hash": "blake3:40c5cb8bceaf83027f39dfe211e07f38a905221807f459707109dc4644158c29",
            "original_byte_start": 32, "original_byte_end": 52,
            "decoded_char_start": 14, "decoded_char_end": 24,
            "line_start": 3, "line_end": 4, "input_bytes": 20
        }
    ]);
    assert_eq!(serde_json::to_value(&chunks).unwrap(), expected);
    assert_eq!(
        chunks
            .iter()
            .map(|c| (c.decoded_byte_start, c.decoded_byte_end))
            .collect::<Vec<_>>(),
        [(0, 12), (9, 21), (18, 28)]
    );
    assert_eq!(
        chunks,
        iter_chunks("unicode.txt", &content, &config).collect::<Vec<_>>()
    );
}

#[test]
fn tiny_chunks_and_large_overlaps_always_advance_without_coverage_gaps() {
    for text in ["😀😀😀", "alpha\nβeta\n😀 gamma\ndelta"] {
        let content = decode(text.as_bytes()).unwrap();
        let max_chunks = text.chars().count();
        for target_bytes in 1..=20 {
            for overlap_bytes in 0..target_bytes {
                for prefer_line_boundaries in [false, true] {
                    let config = ChunkingConfig {
                        target_bytes,
                        overlap_bytes,
                        prefer_line_boundaries,
                    };
                    let chunks: Vec<_> = iter_chunks("progress", &content, &config)
                        .take(max_chunks + 1)
                        .collect();
                    assert!(chunks.len() <= max_chunks, "{config:?}");
                    assert_eq!(chunks[0].decoded_byte_start, 0);
                    assert_eq!(chunks.last().unwrap().decoded_byte_end, text.len());
                    for chunk in &chunks {
                        assert!(chunk.decoded_byte_end > chunk.decoded_byte_start);
                        assert!(text.is_char_boundary(chunk.decoded_byte_start));
                        assert!(text.is_char_boundary(chunk.decoded_byte_end));
                    }
                    for pair in chunks.windows(2) {
                        assert!(
                            pair[1].decoded_byte_start > pair[0].decoded_byte_start,
                            "{config:?}"
                        );
                        assert!(
                            pair[1].decoded_byte_start <= pair[0].decoded_byte_end,
                            "{config:?}"
                        );
                    }
                }
            }
        }
    }
}
