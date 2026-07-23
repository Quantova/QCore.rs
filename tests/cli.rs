//! The terminal client is user facing, so its address prose must name the uppercase Q1 form. The

#![cfg(feature = "client")]

use std::process::Command;

#[test]
fn the_balance_command_names_the_uppercase_q1_form_on_a_bad_address() {
    let output = Command::new(env!("CARGO_BIN_EXE_qcore"))
        .args(["balance", "http://127.0.0.1:1", "notanaddress"])
        .output()
        .expect("run the qcore binary");
    assert!(!output.status.success(), "a bad address exits non zero");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Q1 address"), "unexpected stderr: {stderr}");
    assert!(!stderr.contains("q1 address"), "the prose keeps the prefix uppercase");
}
