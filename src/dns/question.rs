use crate::buffer::PacketBuffer;

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
