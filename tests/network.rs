// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![cfg(feature = "client")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use qcore::{account_address, Client, Network, MAINNET_CHAIN_NAME};

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

fn spawn_gateway(reported_chain: &'static str) -> (u16, Arc<AtomicUsize>) {
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
                    "{{\"chain_id\":\"{reported_chain}\",\"genesis_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
                     \"head_height\":10,\"denomination\":\"Quon\",\
                     \"fee\":{{\"transfer_quon\":\"100\"}},\"version\":\"test\",\"protocol\":2}}"
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

fn mainnet_at(base: &str) -> Network {
    Network {
        name: "mainnet".to_string(),
        chain_id: Some("Q-main-net-1".to_string()),
        rpc_url: Some(base.to_string()),
        explorer_url: None,
        denomination: "Quon".to_string(),
        decimals: 6,
        is_mainnet: true,
        genesis_hash: Some([0u8; 32]),
        roster_commitment: None,
        epoch_length: None,
    }
}

#[test]
fn a_testnet_network_carries_its_identifiers() {
    let testnet = Network::testnet();
    assert_eq!(
        testnet.chain_id.as_deref(),
        Some("Q-test-net-01"),
        "testnet chain id"
    );
    assert_eq!(
        testnet.rpc_url.as_deref(),
        Some(qcore::TESTNET_RPC_URL),
        "testnet names the same public endpoint in every client"
    );
    assert_eq!(testnet.denomination, "Quon", "testnet denomination");
    assert_eq!(testnet.decimals, 6, "testnet decimals are six");
    assert!(!testnet.is_mainnet, "testnet is not mainnet");
    assert!(Network::mainnet().is_mainnet, "mainnet is flagged");
}

#[test]
fn a_client_from_a_network_carries_that_network() {
    let client = Client::with_network("http://127.0.0.1:1", Network::testnet(), false);
    assert_eq!(
        client.network().chain_id.as_deref(),
        Some("Q-test-net-01"),
        "the client carries its configured network"
    );
    let refused = Client::for_network(Network::testnet(), false)
        .err()
        .expect("the built in loopback transport cannot reach the https testnet endpoint");
    assert!(refused.contains("for_network_with_transport"), "{refused}");
    struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl qcore::Transport for Recorder {
        fn post(&self, base: &str, path: &str, _body: &str) -> Result<(u16, String), String> {
            self.0.lock().unwrap().push(format!("{base}{path}"));
            Err("recorded".to_string())
        }
    }
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let through = Client::for_network_with_transport(
        Network::testnet(),
        false,
        Box::new(Recorder(seen.clone())),
    )
    .expect("a supplied transport reaches the https endpoint");
    assert!(through.node_info().is_err());
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        [format!("{}/v1/node_info", qcore::TESTNET_RPC_URL)]
    );
}

#[test]
fn a_mainnet_network_client_is_refused_without_acknowledgement_and_opens_with_it() {
    let live = mainnet_at("http://127.0.0.1:1");
    assert!(
        Client::for_network(live.clone(), false).is_err(),
        "a mainnet client without acknowledgement is refused"
    );
    assert!(
        Client::for_network(live, true).is_ok(),
        "a mainnet client opens with acknowledgement"
    );
}

#[test]
fn a_configured_mainnet_is_refused_when_not_acknowledged_whatever_the_gateway_reports() {
    let (port, submits) = spawn_gateway("Q-test-net-01");
    let base = format!("http://127.0.0.1:{port}");
    let client = Client::with_network(base, mainnet_at("http://placeholder"), false);
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);
    let err = client
        .transfer(&seed, 0, &to, 1000, 1000)
        .expect_err("a configured mainnet without acknowledgement must refuse to sign");
    assert!(
        err.contains("without acknowledging"),
        "unexpected error: {err}"
    );
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "a refused mainnet transfer must never reach submit"
    );
}

#[test]
fn a_plain_url_client_is_refused_a_mainnet_gateway_until_acknowledged() {
    let (port, submits) = spawn_gateway(MAINNET_CHAIN_NAME);
    let base = format!("http://127.0.0.1:{port}");
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);

    let client = Client::new(base.clone());
    let err = client
        .transfer(&seed, 0, &to, 1000, 1000)
        .expect_err("a url client must refuse a mainnet gateway it did not acknowledge");
    assert!(err.contains("mainnet"), "the refusal names mainnet: {err}");
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "nothing is submitted without acknowledgement"
    );

    let acked = Client::with_network(base.clone(), Network::for_url(base), true);
    let err = acked
        .transfer(&seed, 0, &to, 1000, 1000)
        .expect_err("an acknowledged url client still needs a trusted roster for mainnet");
    assert!(err.contains("trusted validator roster"), "{err}");
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "nothing reaches mainnet without a trusted roster"
    );
}

#[test]
fn a_configured_network_refuses_a_mismatched_gateway_chain_id() {
    let (port, submits) = spawn_gateway("Q-main-net-1");
    let base = format!("http://127.0.0.1:{port}");
    let client = Client::with_network(base, Network::testnet(), false);
    let seed = [11u8; 32];
    let to = account_address(&seed, 1);
    let err = client.transfer(&seed, 0, &to, 1000, 1000).expect_err(
        "a gateway chain id that does not match the configured network must be refused",
    );
    assert!(err.contains("did not choose"), "unexpected error: {err}");
    assert_eq!(
        submits.load(Ordering::SeqCst),
        0,
        "a mismatched chain id must never reach submit"
    );
}

#[test]
fn a_zero_transfer_is_refused_and_a_lookalike_is_flagged() {
    let seed = [21u8; 32];
    let to = account_address(&seed, 1);
    assert!(qcore::sign_transfer(
        &seed,
        0,
        &to,
        0,
        0,
        500,
        qcore::testnet_chain_id(),
        100,
        0,
        &[0u8; 32]
    )
    .is_err());
    let known = vec![to.clone()];
    assert_eq!(
        qcore::lookalike_of(&to, &known),
        None,
        "the same address is not a lookalike"
    );
    assert!(qcore::same_address(&to, &to.to_ascii_lowercase()));
    let mut fake = None;
    for i in 2..4_000_000u64 {
        let payload = qtv_crypto::sha3::sha3_256(&i.to_le_bytes());
        let candidate = qtv_idfmt::render_address(&payload).unwrap();
        if candidate[2..4] == to[2..4] {
            fake = Some(candidate);
            break;
        }
    }
    let partial = fake.expect("a two character prefix match is cheap to find");
    assert_eq!(
        qcore::lookalike_of(&partial, &known),
        None,
        "sharing only two leading characters is not flagged"
    );
}
