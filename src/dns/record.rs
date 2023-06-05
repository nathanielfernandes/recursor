use std::net::{Ipv4Addr, Ipv6Addr};

use crate::buffer::PacketBuffer;

use super::question::QueryType;

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
