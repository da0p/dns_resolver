use dns_resolver::client::message::DnsMessage;
#[test]
fn encode_valid_address() {
    let enc_addr = DnsMessage::encode_address("dns.google.com");
    assert_eq!(enc_addr[0], 3);
    assert_eq!(enc_addr[1..4], ['d' as u8, 'n' as u8, 's' as u8]);
    assert_eq!(enc_addr[4], 6);
    assert_eq!(
        enc_addr[5..11],
        ['g' as u8, 'o' as u8, 'o' as u8, 'g' as u8, 'l' as u8, 'e' as u8]
    );
    assert_eq!(enc_addr[11], 3);
    assert_eq!(enc_addr[12..15], ['c' as u8, 'o' as u8, 'm' as u8]);
}

#[test]
fn decode_valid_address() {
    let enc_addr = DnsMessage::encode_address("dns.google.com");
    assert_eq!(DnsMessage::decode_address(&enc_addr), "dns.google.com");
}

#[test]
fn encode_invalid_address() {
    let enc_addr = DnsMessage::encode_address("abc");
    assert_eq!(enc_addr[0..5], [3, 'a' as u8, 'b' as u8, 'c' as u8, 0]);
}

#[test]
fn decode_invalid_address() {
    let enc_addr = DnsMessage::encode_address("abc");
    assert_eq!(DnsMessage::decode_address(&enc_addr), "abc");
}

#[test]
fn encode_another_invalid_address() {
    let enc_addr = DnsMessage::encode_address(".abc");
    assert_eq!(enc_addr[0..5], [3, 'a' as u8, 'b' as u8, 'c' as u8, 0]);
}

#[test]
fn parse_dns_response() {
    let response_bytes = vec![
        0x00, 0x16, 0x80, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x64, 0x6e,
        0x73, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x14, 0x00, 0x04, 0x08,
        0x08, 0x08, 0x08, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x14, 0x00, 0x04,
        0x08, 0x08, 0x04, 0x04,
    ];

    let dns_response = DnsMessage::parse(&response_bytes).unwrap();
    let q_name = DnsMessage::decode_address(&dns_response.question.q_name);
    println!("address: {}", q_name);
    let answers = dns_response.answers;
    println!("IP Address:");
    for answer in answers {
        let ip_addr = answer
            .rr_rdata
            .iter()
            .map(|&seg| seg.to_string())
            .collect::<Vec<String>>()
            .join(".");
        println!("{}", ip_addr);
    }
}
