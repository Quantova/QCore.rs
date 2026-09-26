// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
                    l.strip_prefix("content-length:")
                        .map(|v| v.trim().to_string())
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
                    "{{\"chain_id\":\"Q-dev-net-1\",\"genesis_hash\":\"Qgen\",\"head_height\":10,\
                     \"denomination\":\"Quon\",\"fee\":{{\"transfer_quon\":\"{fee_quon}\"}},\
                     \"version\":\"test\"}}"
                ),
                "/v1/get_account" => {
                    let addr = request
                        .rsplit_once("\"address\":\"")
                        .and_then(|(_, rest)| rest.split('"').next())
                        .unwrap_or("Q1acct")
                        .to_string();
                    format!(
                        "{{\"address\":\"{addr}\",\"nonce\":0,\"balance\":\"0\",\
                         \"scheme\":1,\"has_key\":true}}"
                    )
                }
                "/v1/submit_transaction" => {
                    submits_for_thread.fetch_add(1, Ordering::SeqCst);
                    "{\"verdict\":\"accepted\",\"state\":\"fresh\",\"tx_id\":\"Qtxabc\"}"
                        .to_string()
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

#[test]
fn an_expected_nonce_the_gateway_has_not_reached_is_refused() {
    let (port, submits) = spawn_gateway(1000);
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);

    let err = client
        .transfer_expecting(&seed, 0, &to, 1000, 1000, Some(5))
        .expect_err("the mempool admits only the nonce the account has reached");
    assert!(err.contains("you expected 5"), "unexpected error: {err}");
    assert_eq!(submits.load(Ordering::SeqCst), 0);
    let (_signed, outcome) = client
        .transfer_expecting(&seed, 0, &to, 1000, 1000, Some(0))
        .expect("the reported nonce signs");
    assert!(matches!(outcome, Submit::Accepted { .. }));
    assert_eq!(submits.load(Ordering::SeqCst), 1);
}

#[test]
fn every_client_signing_path_expires_a_window_past_the_head() {
    let (port, _) = spawn_gateway(500);
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);
    let chain_id = qcore::chain_id_from_name("Q-dev-net-1");
    let until = 10 + qcore::DEFAULT_VALIDITY_BLOCKS;
    let call_fee = qcore::vm_call_fee(500, 21_000);

    let (signed, _) = client.transfer(&seed, 0, &to, 1000, 1000).unwrap();
    let expected = qcore::sign_transfer(&seed, 0, &to, 1000, 0, 500, chain_id, until).unwrap();
    assert_eq!(signed.tx_bytes, expected.tx_bytes);

    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let (signed, _) = client
        .call(&seed, 0, &to, vec![1, 2], 21_000, call_fee)
        .unwrap();
    let expected = qcore::sign_call(
        &seed,
        0,
        &to,
        vec![1, 2],
        0,
        21_000,
        call_fee,
        chain_id,
        until,
        500,
    )
    .unwrap();
    assert_eq!(signed.tx_bytes, expected.tx_bytes);

    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let (signed, _) = client.register(&seed, 0, 1000).unwrap();
    let expected = qcore::sign_register(&seed, 0, 0, 500, chain_id, until).unwrap();
    assert_eq!(signed.tx_bytes, expected.tx_bytes);

    assert!(
        qcore::sign_register(&seed, 0, 0, 500, chain_id, 0).is_err(),
        "a deadline that never expires is refused"
    );
    let later = qcore::sign_register(&seed, 0, 0, 500, chain_id, until + 1).unwrap();
    assert_ne!(
        signed.tx_bytes, later.tx_bytes,
        "the window is signed, not implied"
    );
}

#[test]
fn a_rejected_submission_releases_its_nonce_for_the_next_send() {
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
                "/v1/node_info" => "{\"chain_id\":\"Q-dev-net-1\",\"genesis_hash\":\"Qgen\",\
                     \"head_height\":10,\"denomination\":\"Quon\",\
                     \"fee\":{\"transfer_quon\":\"500\"},\"version\":\"test\"}"
                    .to_string(),
                "/v1/get_account" => {
                    let addr = request
                        .rsplit_once("\"address\":\"")
                        .and_then(|(_, rest)| rest.split('"').next())
                        .unwrap_or("Q1acct")
                        .to_string();
                    format!(
                        "{{\"address\":\"{addr}\",\"nonce\":0,\"balance\":\"0\",\
                         \"scheme\":1,\"has_key\":true}}"
                    )
                }
                "/v1/submit_transaction" => {
                    if submits_for_thread.fetch_add(1, Ordering::SeqCst) == 0 {
                        "{\"verdict\":\"rejected\",\"reason\":\"insufficient_funds\"}".to_string()
                    } else {
                        "{\"verdict\":\"accepted\",\"state\":\"fresh\",\"tx_id\":\"Qtxabc\"}"
                            .to_string()
                    }
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
        }
    });
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);
    let (_signed, first) = client.transfer(&seed, 0, &to, 1000, 1000).unwrap();
    assert!(matches!(first, Submit::Rejected { .. }));
    let (_signed, second) = client
        .transfer(&seed, 0, &to, 2000, 1000)
        .expect("a rejected send must not block the next one at the same nonce");
    assert!(matches!(second, Submit::Accepted { .. }));
    let err = client
        .transfer(&seed, 0, &to, 3000, 1000)
        .expect_err("an accepted send still holds its nonce");
    assert!(err.contains("already signed"), "unexpected error: {err}");
    assert_eq!(submits.load(Ordering::SeqCst), 2);
}

#[test]
fn a_contract_call_refuses_a_ceiling_below_its_meter_fee() {
    let (port, submits) = spawn_gateway(500);
    let client = Client::new(format!("http://127.0.0.1:{port}"));
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);
    let err = client
        .call_payable_expecting(&seed, 0, &to, vec![1], 0, 21_000, 1000, None)
        .expect_err("the meter fee is above a ceiling of one transfer fee");
    assert!(err.contains("above the maximum"), "unexpected error: {err}");
    assert_eq!(submits.load(Ordering::SeqCst), 0);
    assert!(client
        .call_payable_expecting(&seed, 0, &to, vec![1], 0, 21_000, 9_000, Some(0))
        .is_ok());
}
