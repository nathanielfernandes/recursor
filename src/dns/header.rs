use packed_struct::prelude::*;

use crate::buffer::PacketBuffer;

#[derive(PrimitiveEnum_u8, Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,  // no error condition
    FORMERR = 1,  // format error - the name server was unable to interpret the query
    SERVFAIL = 2, // server failure - the name server was unable to process this query due to a problem with the name server
    NXDOMAIN = 3, // name error - meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist
    NOTIMP = 4,   // not implemented - the name server does not support the requested kind of query
    REFUSED = 5, // refused - the name server refuses to perform the specified operation for policy reasons
}

impl ResultCode {
    #[inline]
    pub fn from_u8(val: u8) -> ResultCode {
        match val {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}

#[derive(PackedStruct, Clone, Copy, Debug, PartialEq, Eq)]
#[packed_struct(bit_numbering = "msb0")]
pub struct DnsHeader {
    #[packed_field(bits = "0..=15", endian = "msb")]
    pub id: u16, // identification number; 16 bits

    #[packed_field(bits = "16")]
    pub qr: bool, // query (0) or response (1); 1 bit

    #[packed_field(bits = "17..=20")]
    pub opcode: Integer<u8, packed_bits::Bits<4>>, // operation code; 4 bits

    #[packed_field(bits = "21")]
    pub aa: bool, // authoritative answer; 1 bit
    #[packed_field(bits = "22")]
    pub tc: bool, // truncated; 1 bit
    #[packed_field(bits = "23")]
    pub rd: bool, // recursion desired; 1 bit
    #[packed_field(bits = "24")]
    pub ra: bool, // recursion available; 1 bit

    #[packed_field(bits = "25..=27")]
    pub z: Integer<u8, packed_bits::Bits<3>>, // reserved for future use; 3 bits

    #[packed_field(bits = "28..=31", endian = "msb", ty = "enum")]
    pub rcode: ResultCode, // response code; 4 bits

    #[packed_field(bits = "32..=47", endian = "msb")]
    pub qdcount: u16, // number of entries in the question section; 16 bits
    #[packed_field(bits = "48..=63", endian = "msb")]
    pub ancount: u16, // number of resource records in the answer section; 16 bits
    #[packed_field(bits = "64..=79", endian = "msb")]
    pub nscount: u16, // number of name server resource records in the authority records section; 16 bits
    #[packed_field(bits = "80..=95", endian = "msb")]
    pub arcount: u16, // number of resource records in the additional records section; 16 bits
}

impl DnsHeader {
    pub fn new() -> Self {
        DnsHeader {
            id: 0,
            qr: false,
            opcode: 0.into(),
            aa: false,
            tc: false,
            rd: false,
            ra: false,

            z: 0.into(),

            rcode: ResultCode::NOERROR,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }

    pub fn read(buf: &mut PacketBuffer) -> Result<Self, &'static str> {
        let buf = buf.read_slice::<12>()?;
        match DnsHeader::unpack(&buf) {
            Ok(header) => Ok(header),
            Err(_) => Err("Failed to unpack header"),
        }
    }

    pub fn write(&self, buf: &mut PacketBuffer) -> Result<(), &'static str> {
        match self.pack() {
            Ok(packed) => {
                buf.write_slice(&packed)?;
                Ok(())
            }
            Err(_) => Err("Failed to pack header"),
        }
    }
}
