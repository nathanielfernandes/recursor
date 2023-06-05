use std::net::UdpSocket;

use recursor::{handle_query, rootserver};

fn main() {
    // Bind an UDP socket on port 2053
    let listen_socket = UdpSocket::bind(("0.0.0.0", 2053)).unwrap();

    // Bind an UDP socket on port 43210 for sending queries
    let send_socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();

    // The root server we will be querying
    let ns = rootserver::A;

    // For now, queries are handled sequentially, so an infinite loop for servicing
    // requests is initiated.
    loop {
        match handle_query(ns, &listen_socket, &send_socket) {
            Ok(_) => {}
            Err(e) => eprintln!("An error occurred: {}", e),
        }
    }
}
