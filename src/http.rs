//! A small HTTP client over the standard library, for native use and for proving the

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// POST a JSON body to a base and a path, returning the status code and the response
pub fn post(base: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    let hostport = base
        .strip_prefix("http://")
        .ok_or("the base must start with http://")?;
    let (host, port) = split_hostport(hostport)?;

    let mut stream = TcpStream::connect((host, port)).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .ok();
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        len = body.len(),
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("read: {e}"))?;
    let text = String::from_utf8_lossy(&raw).to_string();

    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("no status line in the response")?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Split a `host:port`, defaulting to no port only when one is given.
fn split_hostport(hostport: &str) -> Result<(&str, u16), String> {
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or("the base must be host:port")?;
    let port = port.parse::<u16>().map_err(|_| "the port is not a number")?;
    Ok((host, port))
}
