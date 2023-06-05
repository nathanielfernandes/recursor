use std::net::{Ipv4Addr, UdpSocket};

use dns::{DnsPacket, QueryType};

pub mod dns;
pub mod packetbuff;

pub fn lookup<S: Into<String>>(
    qname: S,
    qtype: QueryType,
    server: (Ipv4Addr, u16),
    socket: &UdpSocket,
) -> Result<DnsPacket, &'static str> {
    // query packet
    let mut packet = DnsPacket::new();
    packet.header.id = 1234;
    packet.header.rd = true;
    packet.add_question(dns::DnsQuestion::new(qname.into(), qtype));

    // write our packet to a buffer
    let mut req_buf = packetbuff::PacketBuffer::new();
    packet.write(&mut req_buf)?;

    // send our query packet
    socket
        .send_to(req_buf.as_slice(), server)
        .map_err(|_| "failed to send")?;

    // receive the response
    let mut res_buf = packetbuff::PacketBuffer::new();
    socket
        .recv_from(&mut res_buf.buf)
        .map_err(|_| "failed to recv")?;

    // parse the response
    DnsPacket::read(&mut res_buf)
}

pub fn recursive_lookup<S: AsRef<str>>(
    qname: S,
    qtype: QueryType,
    ns: Ipv4Addr,
    socket: &UdpSocket,
) -> Result<DnsPacket, &'static str> {
    let qname = qname.as_ref();
    let mut ns = ns;
    loop {
        println!("Looking up {} {:?} from {}", qname, qtype, ns);

        let server = (ns, 53);
        let response = lookup(qname, qtype, server, socket)?;

        // check if we have any answers and no errors
        if response.header.rcode == dns::ResultCode::NOERROR && !response.answers.is_empty() {
            return Ok(response);
        }

        // check for NXDOMAIN (Name Error)
        if response.header.rcode == dns::ResultCode::NXDOMAIN {
            return Ok(response);
        }

        // find the next nameserver to query
        if let Some(nsaddr) = response.get_resolved_ns(qname) {
            ns = nsaddr;
            continue;
        }

        // check if we have any errors
        let new_ns = match response.get_unresolved_ns(qname) {
            Some(nsname) => nsname,
            None => return Ok(response),
        };

        // recurse to find the next nameserver
        let recursive_response = recursive_lookup(new_ns, QueryType::A, ns, socket)?;

        // check if we have any answers
        if let Some(nsaddr) = recursive_response.get_any_a() {
            ns = nsaddr;
        } else {
            return Ok(recursive_response);
        }
    }
}

pub fn handle_query(
    ns: Ipv4Addr,
    listen_socket: &UdpSocket,
    query_socket: &UdpSocket,
) -> Result<(), &'static str> {
    // receive a query packet
    let mut req_buffer = packetbuff::PacketBuffer::new();
    let (_, src) = listen_socket
        .recv_from(&mut req_buffer.buf)
        .map_err(|_| "failed to recv")?;

    // parse the query packet
    let mut req_packet = DnsPacket::read(&mut req_buffer)?;

    // check if we have any questions
    if req_packet.questions.is_empty() {
        return Err("received packet with no questions");
    }

    // create a response packet
    let mut res_packet = DnsPacket::new();
    res_packet.header.id = req_packet.header.id; // copy the request id
    res_packet.header.rd = true; // set recursion desired
    res_packet.header.ra = true; // set recursion available
    res_packet.header.qr = true; // set response flag

    // check question
    if let Some(question) = req_packet.questions.pop() {
        println!("Received query for {} {:?}", question.qname, question.qtype);

        if let Ok(result) = recursive_lookup(&question.qname, question.qtype, ns, query_socket) {
            res_packet.add_question(question);
            res_packet.header.rcode = result.header.rcode;

            for answer in result.answers {
                res_packet.add_answer(answer);
            }

            for authority in result.authorities {
                res_packet.add_authority(authority);
            }

            for additional in result.additionals {
                res_packet.add_additional(additional);
            }
        } else {
            res_packet.header.rcode = dns::ResultCode::SERVFAIL;
        }
    } else {
        res_packet.header.rcode = dns::ResultCode::FORMERR;
    }

    // write our response packet to a buffer
    let mut res_buffer = packetbuff::PacketBuffer::new();
    res_packet.write(&mut res_buffer)?;

    // send our response packet
    listen_socket
        .send_to(res_buffer.as_slice(), src)
        .map_err(|_| "failed to send")?;

    Ok(())
}

// root servers
pub mod rootserver {
    use std::net::Ipv4Addr;

    pub const A: Ipv4Addr = Ipv4Addr::new(198, 41, 0, 4);
    pub const B: Ipv4Addr = Ipv4Addr::new(199, 9, 14, 201);
    pub const C: Ipv4Addr = Ipv4Addr::new(192, 33, 4, 12);
    pub const D: Ipv4Addr = Ipv4Addr::new(199, 7, 91, 13);
    pub const E: Ipv4Addr = Ipv4Addr::new(192, 203, 230, 10);
    pub const F: Ipv4Addr = Ipv4Addr::new(192, 5, 5, 241);
    pub const G: Ipv4Addr = Ipv4Addr::new(192, 112, 36, 4);
    pub const H: Ipv4Addr = Ipv4Addr::new(198, 97, 190, 53);
    pub const I: Ipv4Addr = Ipv4Addr::new(192, 36, 148, 17);
    pub const J: Ipv4Addr = Ipv4Addr::new(192, 58, 128, 30);
    pub const K: Ipv4Addr = Ipv4Addr::new(193, 0, 14, 129);
    pub const L: Ipv4Addr = Ipv4Addr::new(199, 7, 83, 42);
    pub const M: Ipv4Addr = Ipv4Addr::new(202, 12, 27, 33);
}
