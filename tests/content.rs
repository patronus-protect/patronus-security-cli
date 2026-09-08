use patronus_security_scanner::content::{decode, obvious_binary, Encoding};

#[test]
fn decodes_utf8_bom_strictly() {
    let decoded = decode(b"\xef\xbb\xbfGr\xc3\xbc\xc3\x9fe").unwrap();
    assert_eq!(decoded.text, "Grüße");
    assert_eq!(decoded.encoding, Encoding::Utf8);
    assert_eq!(decoded.original_offset(decoded.text.len()), 10);
}

#[test]
fn decodes_utf16_both_endiannesses_with_offsets() {
    let le = decode(&[0xff, 0xfe, b'A', 0, 0x3d, 0xd8, 0x00, 0xde]).unwrap();
    let be = decode(&[0xfe, 0xff, 0, b'A', 0xd8, 0x3d, 0xde, 0x00]).unwrap();
    assert_eq!(le.text, "A😀");
    assert_eq!(be.text, "A😀");
    assert_eq!(le.original_offset(le.text.len()), 8);
    assert_eq!(be.original_offset(be.text.len()), 8);
}

#[test]
fn rejects_invalid_text_and_detects_binary() {
    assert!(decode(&[0xff]).is_err());
    assert!(obvious_binary(b"abc\0def"));
    assert!(!obvious_binary(&[0xff, 0xfe, b'A', 0]));
}
