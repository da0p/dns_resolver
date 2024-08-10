use dns_resolver::client::question;

#[test]
fn create_question() {
    let name = vec!['h' as u8, 'e' as u8, 'l' as u8, 'l' as u8, 'o' as u8];
    let question = question::Question {
        q_name: name,
        q_type: 1,
        q_class: 1,
    };

    let mut bytes = question.q_name.to_vec();
    bytes.push(0x00);
    bytes.push(0x01);
    bytes.push(0x00);
    bytes.push(0x01);
    assert_eq!(question.to_be_bytes(), bytes);
}
