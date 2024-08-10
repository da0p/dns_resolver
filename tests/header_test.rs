use dns_resolver::client::header;

#[test]
fn create_header() {
    let dns_flags = header::Flag {
        qr: 0,
        op_code: 0,
        aa: 0,
        tc: 0,
        rd: 1,
        ra: 0,
        z: 0,
        r_code: 0,
    };

    let dns_header = header::Header {
        id: 1,
        flags: dns_flags,
        qd_cnt: 1,
        an_cnt: 0,
        ns_cnt: 0,
        ar_cnt: 0,
    };

    assert_eq!(
        dns_header.to_be_bytes(),
        vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}
