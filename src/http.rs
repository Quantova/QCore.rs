// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const MAX_RESPONSE: usize = 8 * 1024 * 1024;

const TIMEOUT: Duration = Duration::from_secs(20);

pub fn post(base: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    if path.contains(['\r', '\n']) {
        return Err("the path carries a line break".to_string());
    }
    let hostport = base.strip_prefix("http://").ok_or_else(|| {
        if base.starts_with("https://") {
            "the built in transport speaks plaintext http to a loopback node only, so reach an https gateway by supplying a TLS transport with Client::with_transport".to_string()
        } else {
            "the base must start with http://".to_string()
        }
    })?;
    if hostport.contains(['\r', '\n', '/', '?', '#', '@', ' ']) {
        return Err("the base must be http://host:port with nothing after the port".to_string());
    }
    let (host, port) = split_hostport(hostport)?;

    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve: {e}"))?
        .next()
        .ok_or("the host did not resolve")?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "refusing plaintext to a non-loopback gateway ({host}); its fee and nonce would be \
             unauthenticated and rewritable to drain funds, use a loopback node or a secure tunnel"
        ));
    }
    let mut stream =
        TcpStream::connect_timeout(&addr, TIMEOUT).map_err(|e| format!("connect: {e}"))?;
    stream.set_read_timeout(Some(TIMEOUT)).ok();
    stream.set_write_timeout(Some(TIMEOUT)).ok();
    let host_header = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host_header}\r\n\
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

    let deadline = Instant::now() + TIMEOUT;
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or("the response timed out")?;
        stream.set_read_timeout(Some(remaining)).ok();
        let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE {
            return Err("the response is too large".to_string());
        }
        raw.extend_from_slice(&buf[..n]);
    }
    parse_response(&raw)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(crate) fn parse_response(raw: &[u8]) -> Result<(u16, String), String> {
    let split = find(raw, b"\r\n\r\n").ok_or("the response has no end of headers")?;
    let head =
        std::str::from_utf8(&raw[..split]).map_err(|_| "the response headers are not UTF-8")?;
    let mut lines = head.split("\r\n");
    let mut status_line = lines.next().unwrap_or("").splitn(3, ' ');
    if !matches!(status_line.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err("the response has no HTTP status line".to_string());
    }
    let code = status_line.next().unwrap_or("");
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err("no status code in the response".to_string());
    }
    let status: u16 = code.parse().map_err(|_| "no status code in the response")?;
    if status < 200 {
        return Err(format!(
            "the gateway sent an interim status {status} that this client never asks for"
        ));
    }
    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("a response header has no name and value")?;
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err("the response content length is not a number".to_string());
            }
            let n: usize = value
                .parse()
                .map_err(|_| "the response content length is out of range")?;
            if length.is_some_and(|m| m != n) {
                return Err("the response carries two different content lengths".to_string());
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") || chunked {
                return Err(
                    "the response uses a transfer encoding this client does not read".to_string(),
                );
            }
            chunked = true;
        }
    }
    let body = &raw[split + 4..];
    let body = match (chunked, length) {
        (true, Some(_)) => {
            return Err(
                "the response carries both a content length and a chunked encoding".to_string(),
            )
        }
        (true, None) => dechunk(body)?,
        (false, Some(n)) if body.len() != n => {
            return Err(format!(
                "the response body is {} bytes but its content length says {n}",
                body.len()
            ))
        }
        _ => body.to_vec(),
    };
    let text = String::from_utf8(body).map_err(|_| "the response is not UTF-8".to_string())?;
    Ok((status, text))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let eol = find(data, b"\r\n").ok_or("a chunk size line is not terminated")?;
        let line = std::str::from_utf8(&data[..eol]).map_err(|_| "a chunk size is not text")?;
        let size_text = line
            .split(';')
            .next()
            .unwrap_or("")
            .trim_matches([' ', '\t']);
        if size_text.is_empty()
            || size_text.len() > 8
            || !size_text.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("a chunk size is not a hexadecimal number".to_string());
        }
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| "a chunk size is out of range")?;
        data = &data[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if data.len() < size + 2 || &data[size..size + 2] != b"\r\n" {
            return Err("a chunk is truncated".to_string());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

fn split_hostport(hostport: &str) -> Result<(&str, u16), String> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("the bracketed host has no closing bracket")?;
        let port = after
            .strip_prefix(':')
            .ok_or("the base must be host:port")?;
        let port = port
            .parse::<u16>()
            .map_err(|_| "the port is not a number")?;
        return Ok((host, port));
    }
    let (host, port) = hostport
        .rsplit_once(':')
        .ok_or("the base must be host:port")?;
    let port = port
        .parse::<u16>()
        .map_err(|_| "the port is not a number")?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::parse_response;

    #[test]
    fn a_response_is_framed_by_its_headers() {
        let ok = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap();
        assert_eq!(ok, (200, "{}".to_string()));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}junk").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n{}").is_err());
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{} "
        )
        .is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}").is_err());
        assert!(parse_response(b"HTTP/1.1 100 Continue\r\n\r\n").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\n{}").is_err());
        assert!(parse_response(b"XTTP/1.1 200 OK\r\n\r\n{}").is_err());
        let chunked = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(chunked.1, "{}");
        assert!(parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{}\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n{}").is_err());
    }
}
