#[test]
fn duration_display_is_stable() {
    assert_eq!(patronus_security_scanner::progress::duration(0), "00:00");
    assert_eq!(patronus_security_scanner::progress::duration(79), "01:19");
}
