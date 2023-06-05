use std::net::{Ipv4Addr, Ipv6Addr};

use packed_struct::prelude::*;

use crate::packetbuff::PacketBuffer;

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

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    #[inline]
    pub fn from_u16(val: u16) -> QueryType {
        match val {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKOWN(val),
        }
    }

    #[inline]
    pub fn to_u16(&self) -> u16 {
        match self {
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
            QueryType::UNKOWN(val) => *val,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: QueryType,
    // pub qclass: u16, always 1
}

impl DnsQuestion {
    pub fn new(qname: String, qtype: QueryType) -> Self {
        DnsQuestion { qname, qtype }
    }

    pub fn read(buf: &mut PacketBuffer) -> Result<Self, &'static str> {
        let mut qname = String::with_capacity(256);
        buf.read_qname(&mut qname)?;

        let qtype = QueryType::from_u16(buf.read_u16()?);
        buf.step(2); // qclass (always 1)

        Ok(DnsQuestion { qname, qtype })
    }

    pub fn write(&self, buf: &mut PacketBuffer) -> Result<(), &'static str> {
        buf.write_qname(&self.qname)?;
        buf.write_u16(self.qtype.to_u16())?;
        buf.write_u16(1)?; // qclass (always 1)
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum DnsRecord {
    UNKOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        ns: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        cname: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        preference: u16,
        exchange: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn read(buf: &mut PacketBuffer) -> Result<Self, &'static str> {
        let mut domain = String::with_capacity(256);
        buf.read_qname(&mut domain)?;

        let qtype = buf.read_u16()?;
        let _qclass = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

        match QueryType::from_u16(qtype) {
            QueryType::A => Ok(DnsRecord::A {
                domain,
                addr: Ipv4Addr::from(buf.read_u32()?),
                ttl,
            }),
            QueryType::AAAA => Ok(DnsRecord::AAAA {
                domain,
                addr: Ipv6Addr::from(buf.read_slice::<16>()?),
                ttl,
            }),
            QueryType::NS => {
                let mut ns = String::with_capacity(256);
                buf.read_qname(&mut ns)?;
                Ok(DnsRecord::NS { domain, ns, ttl })
            }
            QueryType::CNAME => {
                let mut cname = String::with_capacity(256);
                buf.read_qname(&mut cname)?;
                Ok(DnsRecord::CNAME { domain, cname, ttl })
            }
            QueryType::MX => Ok(DnsRecord::MX {
                domain,
                preference: buf.read_u16()?,
                exchange: {
                    let mut exchange = String::with_capacity(256);
                    buf.read_qname(&mut exchange)?;
                    exchange
                },
                ttl,
            }),
            QueryType::UNKOWN(_) => {
                buf.step(data_len as usize);
                Ok(DnsRecord::UNKOWN {
                    domain,
                    qtype,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buf: &mut PacketBuffer) -> Result<usize, &'static str> {
        let start_pos = buf.pos();

        match self {
            DnsRecord::A { domain, addr, ttl } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::A.to_u16())?;
                buf.write_u16(1)?; // qclass (always 1)
                buf.write_u32(*ttl)?;
                buf.write_u16(4)?; // data_len
                buf.write_slice(&addr.octets())?; // data
            }
            DnsRecord::AAAA { domain, addr, ttl } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::AAAA.to_u16())?;
                buf.write_u16(1)?; // qclass (always 1)
                buf.write_u32(*ttl)?;
                buf.write_u16(16)?; // data_len
                buf.write_slice(&addr.octets())?; // data
            }
            DnsRecord::NS { domain, ns, ttl } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::NS.to_u16())?;
                buf.write_u16(1)?; // qclass (always 1)
                buf.write_u32(*ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?; // data_len

                buf.write_qname(ns)?;
                let len = buf.pos() - pos - 2;
                buf.set_u16(pos, len as u16)?;
            }
            DnsRecord::CNAME { domain, cname, ttl } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::CNAME.to_u16())?;
                buf.write_u16(1)?; // qclass (always 1)
                buf.write_u32(*ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?; // data_len

                buf.write_qname(cname)?;
                let len = buf.pos() - pos - 2;
                buf.set_u16(pos, len as u16)?;
            }
            DnsRecord::MX {
                domain,
                preference,
                exchange,
                ttl,
            } => {
                buf.write_qname(domain)?;
                buf.write_u16(QueryType::MX.to_u16())?;
                buf.write_u16(1)?; // qclass (always 1)
                buf.write_u32(*ttl)?;

                let pos = buf.pos();
                buf.write_u16(0)?; // data_len

                buf.write_u16(*preference)?;
                buf.write_qname(exchange)?;

                let len = buf.pos() - pos - 2;
                buf.set_u16(pos, len as u16)?;
            }

            DnsRecord::UNKOWN { .. } => {
                println!("write DnsRecord::UNKOWN not implemented");
            }
        }

        Ok(buf.pos() - start_pos)
    }
}

#[derive(Debug, Clone)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    // get the first A record from the answers
    // it does not matter which one we use
    pub fn get_any_a(&self) -> Option<Ipv4Addr> {
        for answer in &self.answers {
            if let DnsRecord::A { addr, .. } = answer {
                return Some(*addr);
            }
        }
        None
    }

    // iterate over all name servers in the authorities
    pub fn iter_ns<'a>(&'a self, qname: &'a str) -> impl Iterator<Item = (&'a str, &'a str)> {
        self.authorities.iter().filter_map(|record| match record {
            DnsRecord::NS { domain, ns, .. } if qname.ends_with(domain) => {
                Some((domain.as_str(), ns.as_str()))
            }
            _ => None,
        })
    }

    // get the first actual ip for an ns record if it exists
    // look for a matching a record in the additionals
    pub fn get_resolved_ns(&self, qname: &str) -> Option<Ipv4Addr> {
        for (_, ns) in self.iter_ns(qname) {
            for record in &self.additionals {
                if let DnsRecord::A { domain, addr, .. } = record {
                    if domain == ns {
                        return Some(*addr);
                    }
                }
            }
        }
        None
    }

    // get the first unresolved ns record if it exists
    pub fn get_unresolved_ns<'a>(&'a self, qname: &'a str) -> Option<&'a str> {
        self.iter_ns(qname).map(|(_, host)| host).next()
    }

    pub fn read(buf: &mut PacketBuffer) -> Result<Self, &'static str> {
        let header = DnsHeader::read(buf)?;

        let mut queries = Vec::with_capacity(header.qdcount as usize);
        for _ in 0..header.qdcount {
            queries.push(DnsQuestion::read(buf)?);
        }

        let mut answers = Vec::with_capacity(header.ancount as usize);
        for _ in 0..header.ancount {
            answers.push(DnsRecord::read(buf)?);
        }

        let mut authorities = Vec::with_capacity(header.nscount as usize);
        for _ in 0..header.nscount {
            authorities.push(DnsRecord::read(buf)?);
        }

        let mut additionals = Vec::with_capacity(header.arcount as usize);
        for _ in 0..header.arcount {
            additionals.push(DnsRecord::read(buf)?);
        }

        Ok(DnsPacket {
            header,
            questions: queries,
            answers,
            authorities,
            additionals,
        })
    }

    pub fn write(&mut self, buf: &mut PacketBuffer) -> Result<(), &'static str> {
        // skipped, safe to assume that the counts are correct
        // self.header.qdcount = self.questions.len() as u16;
        // self.header.ancount = self.answers.len() as u16;
        // self.header.nscount = self.authorities.len() as u16;
        // self.header.arcount = self.additionals.len() as u16;

        self.header.write(buf)?;

        for q in &self.questions {
            q.write(buf)?;
        }

        for a in &self.answers {
            a.write(buf)?;
        }

        for a in &self.authorities {
            a.write(buf)?;
        }

        for a in &self.additionals {
            a.write(buf)?;
        }

        Ok(())
    }

    pub fn add_question(&mut self, question: DnsQuestion) {
        self.questions.push(question);
        self.header.qdcount += 1;
    }

    pub fn add_answer(&mut self, answer: DnsRecord) {
        self.answers.push(answer);
        self.header.ancount += 1;
    }

    pub fn add_authority(&mut self, authority: DnsRecord) {
        self.authorities.push(authority);
        self.header.nscount += 1;
    }

    pub fn add_additional(&mut self, additional: DnsRecord) {
        self.additionals.push(additional);
        self.header.arcount += 1;
    }
}
