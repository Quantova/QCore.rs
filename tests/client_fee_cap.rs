// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The convenience client must never sign a transfer whose fee the gateway reports above the

#![cfg(feature = "client")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use qcore::{account_address, Client, Submit};

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read one HTTP request, headers and the declared body, so the client's write finishes before the
fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]);
            let content_len = head
                .lines()
                .find_map(|l| {
                    let l = l.to_ascii_lowercase();
                    l.strip_prefix("content-length:").map(|v| v.trim().to_string())
                })
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            if buf.len() - (pos + 4) >= content_len {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Start a loopback gateway that answers the `/v1` methods with canned JSON, reporting the given
fn spawn_gateway(fee_quon: u128) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    let submits = Arc::new(AtomicUsize::new(0));
    let submits_for_thread = submits.clone();
    thread::spawn(move || {
        for conn in listener.incoming() {
            let mut stream = match conn {
                Ok(s) => s,
                Err(_) => continue,
            };
            let request = read_request(&mut stream);
            let path = request
                .lines()
                .next()
                .unwrap_or("")
                .split_whitespace()
                .nth(1)
                .unwrap_or("");
            let body = match path {
                "/v1/node_info" => format!(
                    "{{\"chain_id\":\"Q-test-net-1\",\"genesis_hash\":\"Qgen\",\"head_height\":10,\
                     \"denomination\":\"Quon\",\"fee\":{{\"transfer_quon\":\"{fee_quon}\"}},\
                     \"version\":\"test\"}}"
                ),
                "/v1/get_account" => "{\"address\":\"Q1acct\",\"nonce\":0,\"balance\":\"0\",\
                     \"scheme\":1,\"has_key\":true}"
                    .to_string(),
                "/v1/submit_transaction" => {
                    submits_for_thread.fetch_add(1, Ordering::SeqCst);
                    "{\"verdict\":\"accepted\",\"state\":\"fresh\",\"tx_id\":\"Qtxabc\"}".to_string()
                }
                _ => "{\"error\":\"unknown_method\",\"message\":\"x\"}".to_string(),
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            // Drop the stream, which closes it, so the client sees end of stream and stops reading.
        }
    });
    (port, submits)
}

#[test]
fn transfer_refuses_a_fee_above_the_ceiling_and_never_submits() {
    let (port, submits) = spawn_gateway(5000);
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);

    let err = client
        .transfer(&seed, 0, &to, 1000, 1000)
        .expect_err("a fee of 5000 above a ceiling of 1000 must be refused");
    assert!(err.contains("above the maximum"), "unexpected error: {err}");
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "a refused transfer must never reach submit"
    );
}

#[test]
fn transfer_at_or_below_the_ceiling_signs_and_submits() {
    let (port, submits) = spawn_gateway(1000);
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);

    let (_signed, outcome) = client
        .transfer(&seed, 0, &to, 1000, 1000)
        .expect("a fee equal to the ceiling is allowed");
    match outcome {
        Submit::Accepted { .. } => {}
        other => panic!("expected an accepted submission, got {other:?}"),
    }
    assert_eq!(
        submits.load(Ordering::SeqCst),
        1,
        "an allowed transfer submits exactly once"
    );
}
