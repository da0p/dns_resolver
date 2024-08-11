use std::error::Error;

use crate::client::utility;

/// Flag section in DNS header
pub struct Flag {

    /// Whether it is a query (0) or a response (1)
    pub qr: u16,
    /// Kind of query:
    /// 0 - standard query,
    /// 1 - inverse query,
    /// 2 - server status request
    pub op_code: u16,
    /// Authoritative answer - valid in response
    pub aa: u16,
    /// Truncation - message was truncated due to excessive length
    pub tc: u16,
    /// Recursion desired - direct name server to pursue query recursively
    pub rd: u16,
    /// Recursion availble - denotes whether recursive query support is
    /// available in the name server
    pub ra: u16,
    /// Reserved for future use
    pub z: u16,
    /// Response code
    /// 0 - no error condition
    /// 1 - format error
    /// 2 - server failure
    /// 3 - name error
    /// 4 - not implemented
    /// 5 - refused
    /// 6-15 - reserved for future use
    pub r_code: u16,
}

impl Flag {
    /// Transform the flag to a two-octet number
    pub fn to_be_bytes(&self) -> u16 {
        self.qr << 15
            | self.op_code << 11
            | self.aa << 10
            | self.tc << 9
            | self.rd << 8
            | self.ra << 7
            | self.z << 4
            | self.r_code
    }

    /// Parse a vector bytes to DNS flag
    pub fn parse(flags: &[u8]) -> Flag {
        let flag = utility::to_u16(flags);
        let r_code = utility::get_bits_range(flag, 0, 4);
        let z = utility::get_bits_range(flag, 4, 7);
        let ra = utility::get_bits_range(flag, 7, 8);
        let rd = utility::get_bits_range(flag, 8, 9);
        let tc = utility::get_bits_range(flag, 9, 10);
        let aa = utility::get_bits_range(flag, 10, 11);
        let op_code = utility::get_bits_range(flag, 11, 15);
        let qr = utility::get_bits_range(flag, 15, 16);

        Flag {
            qr,
            op_code,
            aa,
            tc,
            rd,
            ra,
            z,
            r_code,
        }
    }
}

/// DNS Header
pub struct Header {
    /// Identifier from the DNS client
    pub id: u16,
    /// DNS Flag
    pub flags: Flag,
    /// Number of questions
    pub qd_cnt: u16,
    /// Number of answers
    pub an_cnt: u16,
    /// Number of authority records
    pub ns_cnt: u16,
    /// Number of additional records
    pub ar_cnt: u16,
}

impl Header {
    /// Transform to a vector of bytes
    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut header = vec![];

        let mut bytes = self.id.to_be_bytes().to_vec();
        header.append(&mut bytes);

        bytes = self.flags.to_be_bytes().to_be_bytes().to_vec();
        header.append(&mut bytes);

        bytes = self.qd_cnt.to_be_bytes().to_vec();
        header.append(&mut bytes);

        bytes = self.an_cnt.to_be_bytes().to_vec();
        header.append(&mut bytes);

        bytes = self.ns_cnt.to_be_bytes().to_vec();
        header.append(&mut bytes);

        bytes = self.ar_cnt.to_be_bytes().to_vec();
        header.append(&mut bytes);

        header
    }

    /// Parse a vector of bytes to DNS header
    pub fn parse(message: &Vec<u8>, start: usize) -> Result<(usize, Header), Box<dyn Error>> {
        let id = utility::to_u16(&message[start..start + 2]);
        let flags = Flag::parse(&message[start + 2..start + 4]);
        let qd_cnt = utility::to_u16(&message[start + 4..start + 6]);
        let an_cnt = utility::to_u16(&message[start + 6..start + 8]);
        let ns_cnt = utility::to_u16(&message[start + 8..start + 10]);
        let ar_cnt = utility::to_u16(&message[start + 10..start + 12]);

        let h = Header {
            id,
            flags,
            qd_cnt,
            an_cnt,
            ns_cnt,
            ar_cnt,
        };

        Ok((start + 12, h))
    }
}
