use std::net::Ipv4Addr;

use crate::buffer::PacketBuffer;

use super::{header::DnsHeader, question::DnsQuestion, record::DnsRecord};

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
