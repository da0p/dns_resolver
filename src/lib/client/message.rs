use crate::client::header::{Flag, Header};
use crate::client::question::Question;
use crate::client::rr::ResourceRecord;
use std::error::Error;

/// DNS message
pub struct DnsMessage {
    /// DNS header
    pub header: Header,
    /// DNS question section
    pub question: Question,
    /// DNS answer section
    pub answers: Vec<ResourceRecord>,
    /// DNS authority section
    pub authorities: Vec<ResourceRecord>,
    /// DNS additional section
    pub additionals: Vec<ResourceRecord>,
}

impl DnsMessage {
    /// Create a new DNS message
    pub fn new(address: &str) -> DnsMessage {
        let dns_flags = Flag {
            qr: 0,
            op_code: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            r_code: 0,
        };

        let dns_header = Header {
            id: rand::random::<u16>(),
            flags: dns_flags,
            qd_cnt: 1,
            an_cnt: 0,
            ns_cnt: 0,
            ar_cnt: 0,
        };

        let dns_question = Question {
            q_name: DnsMessage::encode_address(address),
            q_type: 1,
            q_class: 1,
        };

        let dns_msg = DnsMessage {
            header: dns_header,
            question: dns_question,
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        dns_msg
    }

    /// Transform a dns message to a vector of bytes
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut msg = vec![];

        let mut bytes = self.header.to_be_bytes();
        msg.append(&mut bytes);

        bytes = self.question.to_be_bytes();
        msg.append(&mut bytes);

        for i in 0..self.header.an_cnt {
            bytes = self.answers[i as usize].to_be_bytes();
            msg.append(&mut bytes);
        }

        for i in 0..self.header.ns_cnt {
            bytes = self.authorities[i as usize].to_be_bytes();
            msg.append(&mut bytes);
        }

        for i in 0..self.header.ar_cnt {
            bytes = self.additionals[i as usize].to_be_bytes();
            msg.append(&mut bytes);
        }

        msg
    }

    /// Fill DNS message into an array of bytes
    pub fn into_bytes(&self) -> [u8; 128] {
        let bytes = self.to_be_bytes();
        let mut buf = [0; 128];
        for i in 0..bytes.len() {
            buf[i] = bytes[i];
        }
        buf
    }

    /// Parse a vector of bytes into a DNS message
    pub fn parse(message: &Vec<u8>) -> Result<DnsMessage, Box<dyn Error>> {
        let mut start = 0;
        let parsed_value= Header::parse(&message, start)?;
        start = parsed_value.0;
        let header = parsed_value.1;

        let parsed_value = Question::parse(&message, start)?;
        start = parsed_value.0;
        let question = parsed_value.1;

        let mut answers = vec![];
        for _ in 0..header.an_cnt {
            let answer = ResourceRecord::parse(&message, start)?;
            answers.push(answer.1);
            start = answer.0;
        }

        let mut authorities = vec![];
        for _ in 0..header.ns_cnt {
            let authority = ResourceRecord::parse(&message, start)?;
            authorities.push(authority.1);
            start = authority.0;
        }

        let mut additionals = vec![];
        for _ in 0..header.ar_cnt {
            let additional = ResourceRecord::parse(&message, start)?;
            additionals.push(additional.1);
            start = additional.0;
        }

        let dns_message = DnsMessage {
            header,
            question,
            answers,
            authorities,
            additionals,
        };

        Ok(dns_message)
    }

    /// Encode an address into the format for DNS
    pub fn encode_address(address: &str) -> Vec<u8> {
        let mut encoded_addr = vec![];
        let segs = address
            .split(".")
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        for seg in segs {
            encoded_addr.push(seg.len() as u8);
            for j in 0..seg.len() {
                encoded_addr.push(seg.chars().nth(j).unwrap() as u8);
            }
        }
        encoded_addr.push(0);

        encoded_addr
    }

    /// Decode an address in DNS message
    pub fn decode_address(bytes: &Vec<u8>) -> String {
        let mut segments = vec![];
        let mut i = 0;
        while bytes[i] != 0 {
            let f_seg_len = bytes[i] as usize;
            if f_seg_len != 0 {
                let seg = String::from_utf8(bytes[i + 1..i + 1 + f_seg_len].to_vec()).unwrap();
                segments.push(seg);
            }
            i += f_seg_len + 1;
        }
        segments.join(".")
    }
}
