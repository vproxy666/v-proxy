use std::net::UdpSocket;
use std::io;
use x509_parser::ASN1Time;
use chrono::prelude::DateTime;
use chrono::Utc;
use std::time::{UNIX_EPOCH, Duration};

pub fn get_local_ip() -> String {
    match get_ip_by_udp() {
        Ok(ip) => ip,
        Err(e) => {
            warn!("get_ip_by_udp() failed. {}", e);
            "127.0.0.1".to_string()
        }
    }
}


/* This approach provides accurate outbound local IP address.
However, this approach may not work on MAC OS, who knows.

Connect an UDP socket has the following effect: 
it sets the destination for Send/Recv, discards all packets from other addresses, 
and - which is what we use - transfers the socket into "connected" state, settings its appropriate fields. 
This includes checking the existence of the route to the destination according to the system's routing table 
and setting the local endpoint accordingly. 
The last part seems to be undocumented officially but it looks like an integral trait of Berkeley sockets API 
(a side effect of UDP "connected" state) that works reliably in both Windows and Linux across versions and distributions.

So, this method will give the local address that would be used to connect to the specified remote host. 
There is no real connection established, hence the specified remote ip can be unreachable.

*/
pub fn get_ip_by_udp() -> io::Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:6611")?;
    socket.connect("8.8.8.8:34254")?;
    let local_addr = socket.local_addr()?;
    Ok(local_addr.ip().to_string())
}

pub fn convert_to_rfc3339(asn1_time : &ASN1Time) -> String {
    // Creates a new SystemTime from the specified number of whole seconds
    let duration = UNIX_EPOCH + Duration::from_secs(asn1_time.timestamp() as u64);
    // Create DateTime from SystemTime
    let datetime = DateTime::<Utc>::from(duration);
    // Formats the combined date and time with the specified format string.
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}