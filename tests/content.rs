use lopdf::{
    content::{Content, Operation},
    dictionary, Document, Object, Stream,
};
use patronus_security_scanner::content::{decode, obvious_binary, Encoding};
use std::io::Write;

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

#[test]
fn extracts_docx_text_without_scanning_the_zip_container() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("document.docx");
    let file = std::fs::File::create(&path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    archive
        .start_file(
            "word/document.xml",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
    archive
        .write_all(br#"<w:document xmlns:w="x"><w:body><w:p><w:r><w:t>Hello &amp; goodbye</w:t></w:r></w:p><w:p><w:r><w:t>Second</w:t></w:r></w:p></w:body></w:document>"#)
        .unwrap();
    archive.finish().unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let decoded = patronus_security_scanner::content::read_decode(&path, size, 1_000_000, &root)
        .unwrap()
        .unwrap();
    assert_eq!(decoded.text, "Hello & goodbye\nSecond\n");
}

#[test]
fn extracts_pdf_text_locally() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("document.pdf");
    let mut document = Document::with_version("1.5");
    let pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Courier",
    });
    let resources_id = document.add_object(dictionary! {
        "Font" => dictionary! { "F1" => font_id },
    });
    let content = Content {
        operations: vec![
            Operation::new("BT", vec![]),
            Operation::new("Tf", vec!["F1".into(), 12.into()]),
            Operation::new("Tj", vec![Object::string_literal("Local PDF text")]),
            Operation::new("ET", vec![]),
        ],
    };
    let content_id = document.add_object(Stream::new(dictionary! {}, content.encode().unwrap()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => pages_id, "Contents" => content_id,
    });
    document.objects.insert(pages_id, Object::Dictionary(dictionary! {
        "Type" => "Pages", "Kids" => vec![page_id.into()], "Count" => 1,
        "Resources" => resources_id, "MediaBox" => vec![0.into(), 0.into(), 595.into(), 842.into()],
    }));
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog", "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    document.save(&path).unwrap();

    let size = std::fs::metadata(&path).unwrap().len();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let decoded = patronus_security_scanner::content::read_decode(&path, size, 1_000_000, &root)
        .unwrap()
        .unwrap();

    assert!(decoded.text.contains("Local PDF text"));
}

#[test]
fn rejects_docx_expansion_above_the_file_limit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("large.docx");
    let file = std::fs::File::create(&path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    archive
        .start_file(
            "word/document.xml",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    archive.write_all(&vec![b'x'; 20_000]).unwrap();
    archive.finish().unwrap();
    let size = std::fs::metadata(&path).unwrap().len();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    assert!(
        patronus_security_scanner::content::read_decode(&path, size, 10_000, &root,)
            .unwrap()
            .is_err()
    );
}
