//! A small HTTP client over the standard library, for native use and for proving the

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The largest reply the client will hold. A gateway reply is small, so this is far above
const MAX_RESPONSE: usize = 8 * 1024 * 1024;

/// The ceiling on connect, read, and write, so a stalled peer cannot hang the client.
const TIMEOUT: Duration = Duration::from_secs(20);

/// POST a JSON body to a base and a path, returning the status code and the response
pub fn post(base: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    if path.contains(['\r', '\n']) {
        return Err("the path carries a line break".to_string());
    }
    let hostport = base
        .strip_prefix("http://")
        .ok_or("the base must start with http://")?;
    if hostport.contains(['\r', '\n']) {
        return Err("the base carries a line break".to_string());
    }
    let (host, port) = split_hostport(hostport)?;

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .next()
        .ok_or("the host did not resolve")?;
    // Refuse plaintext to anything but a loopback node. There is no TLS on this transport, so over an
    // untrusted network a gateway's fee and nonce are unauthenticated and an attacker in the middle can
    // rewrite them to drain the signer. A loopback node is the signer's own machine and is safe. Reach
    // a remote gateway through a secure tunnel that terminates on loopback here.
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing plaintext to a non-loopback gateway ({host}); its fee and nonce would be \
             unauthenticated and rewritable to drain funds, use a loopback node or a secure tunnel"
        ));
    }
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
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
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE {
            return Err("the response is too large".to_string());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&raw).to_string();

    let status_line = text.lines().next().unwrap_or("");
    if !status_line.starts_with("HTTP/") {
        return Err("the response has no HTTP status line".to_string());
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or("no status code in the response")?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

/// Split a `host:port`. An IPv6 literal is bracketed, `[host]:port`, so the host inside the
fn split_hostport(hostport: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("the bracketed host has no closing bracket")?;
        let port = after.strip_prefix(':').ok_or("the base must be host:port")?;
        let port = port.parse::<u16>().map_err(|_| "the port is not a number")?;
        return Ok((host, port));
    }
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or("the base must be host:port")?;
    let port = port.parse::<u16>().map_err(|_| "the port is not a number")?;
    Ok((host, port))
}
