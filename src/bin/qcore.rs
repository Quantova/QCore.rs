// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::{
    account_address, account_public_key, generate_seed, mnemonic_from_seed, valid_address, Client,
    Network, Submit, TxStatus,
};
use zeroize::Zeroizing;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match run(&args[1..]) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str).unwrap_or("help") {
        "new" => cmd_new(),
        "address" => cmd_address(&args[1..]),
        "pubkey" => cmd_pubkey(&args[1..]),
        "info" => cmd_info(&args[1..]),
        "register" => cmd_register(&args[1..]),
        "balance" => cmd_balance(&args[1..]),
        "send" => cmd_send(&args[1..]),
        "status" => cmd_status(&args[1..]),
        "help" | "-h" | "--help" => {
            print_usage();
            Ok(())
        }
        other => {
            print_usage();
            Err(format!("unknown command '{other}'"))
        }
    }
}

fn cmd_new() -> Result<(), String> {
    let seed = generate_seed()?;
    let seed_hex = Zeroizing::new(to_hex(&seed[..]));
    let phrase = Zeroizing::new(mnemonic_from_seed(&seed));
    println!("seed    {}", seed_hex.as_str());
    println!("phrase  {}", phrase.as_str());
    println!("address {}", account_address(&seed, 0));
    println!();
    println!("Keep the seed and the phrase secret. The phrase is the only backup of this key.");
    Ok(())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let seed = read_seed(args.first().ok_or("usage: qcore address <seed> [index]")?)?;
    let index = parse_index(args.get(1))?;
    println!("{}", account_address(&seed, index));
    Ok(())
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let seed = read_seed(args.first().ok_or("usage: qcore pubkey <seed> [index]")?)?;
    let index = parse_index(args.get(1))?;
    println!("scheme  1");
    println!("pubkey  {}", to_hex(&account_public_key(&seed, index)));
    println!("address {}", account_address(&seed, index));
    Ok(())
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    let gateway = args.first().ok_or("usage: qcore info <gateway-url>")?;
    let info = Client::new(gateway.clone()).node_info()?;
    println!("chain   {}", info.chain_id);
    println!("height  {}", info.head_height);
    println!("fee     {} {}", info.transfer_fee, info.denomination);
    println!("version {}", info.version);
    Ok(())
}

fn cmd_register(args: &[String]) -> Result<(), String> {
    let (mainnet, args) = take_flag(args, "--mainnet");
    if args.len() < 3 {
        return Err(
            "usage: qcore register [--mainnet] <gateway-url> <seed-hex> <max-fee>".to_string(),
        );
    }
    let seed = read_seed(&args[1])?;
    // The ceiling is the caller's own, never the gateway's reported fee. Passing the reported fee as
    // the ceiling would compare the fee against itself and sign whatever the gateway asks, which lets
    // a hostile gateway inflate the registration fee to drain the account.
    let max_fee: u128 = args[2].parse().map_err(|_| "the max fee is not a number")?;
    let (_signed, outcome) = build_client(&args[0], mainnet).register(&seed, 0, max_fee)?;
    match outcome {
        Submit::Accepted { state, tx_id } => {
            println!("registered {tx_id}");
            println!("state      {state}");
            Ok(())
        }
        Submit::Rejected { reason, .. } => {
            Err(format!("the node rejected the registration: {reason}"))
        }
    }
}

fn cmd_balance(args: &[String]) -> Result<(), String> {
    let gateway = args.first().ok_or("usage: qcore balance <gateway-url> <address>")?;
    let address = args.get(1).ok_or("usage: qcore balance <gateway-url> <address>")?;
    if !valid_address(address) {
        return Err("the address is not a Q1 address".to_string());
    }
    let account = Client::new(gateway.clone()).account(address)?;
    println!("address {}", account.address);
    println!("balance {}", account.balance);
    println!("nonce   {}", account.nonce);
    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    let (mainnet, args) = take_flag(args, "--mainnet");
    if args.len() < 5 {
        return Err(
            "usage: qcore send [--mainnet] <gateway-url> <seed-hex> <to> <amount> <max-fee>"
                .to_string(),
        );
    }
    let seed = read_seed(&args[1])?;
    let to = &args[2];
    let amount: u64 = args[3].parse().map_err(|_| "the amount is not a number")?;
    let max_fee: u128 = args[4].parse().map_err(|_| "the max fee is not a number")?;
    let (_signed, outcome) = build_client(&args[0], mainnet).transfer(&seed, 0, to, amount, max_fee)?;
    match outcome {
        Submit::Accepted { state, tx_id } => {
            println!("submitted {tx_id}");
            println!("state     {state}");
            Ok(())
        }
        Submit::Rejected { reason, .. } => {
            Err(format!("the node rejected the transfer: {reason}"))
        }
    }
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let gateway = args.first().ok_or("usage: qcore status <gateway-url> <tx-id>")?;
    let tx_id = args.get(1).ok_or("usage: qcore status <gateway-url> <tx-id>")?;
    match Client::new(gateway.clone()).transaction(tx_id)? {
        TxStatus::Finalised { height, block } => {
            println!("finalised at height {height} in block {block}")
        }
        TxStatus::Pending => println!("pending"),
        TxStatus::Unknown => println!("unknown"),
    }
    Ok(())
}

fn print_usage() {
    println!("qcore, the Quantova terminal client");
    println!();
    println!("usage");
    println!("  qcore new                                             create a wallet, seed, phrase, and address");
    println!("  qcore address <seed-hex> [index]                      the address for a seed and index");
    println!("  qcore pubkey <seed-hex> [index]                       the scheme, public key, and address, for genesis");
    println!("  qcore info <gateway-url>                              the chain id, height, and fee");
    println!("  qcore register [--mainnet] <gateway-url> <seed-hex> <max-fee>     register a funded account's key so it can send");
    println!("  qcore balance <gateway-url> <address>                 an account balance and nonce");
    println!("  qcore send [--mainnet] <gateway-url> <seed-hex> <to> <amount> <max-fee>   sign and submit a transfer");
    println!("  qcore status <gateway-url> <tx-id>                    where a transaction is");
    println!();
    println!("A <seed> can be the hex directly, @file to read it from a file, - to read it from");
    println!("stdin, or env:VAR to read it from an environment variable. Prefer the last three so");
    println!("the seed never appears in the process list or your shell history.");
    println!();
    println!("Pass --mainnet on a signing command to bind the client to the Q-main-net-1 network and");
    println!("acknowledge that the transaction moves real value; the command then refuses to sign if");
    println!("the gateway does not serve that network. Without it a signing command follows whatever");
    println!("network the gateway names and does not prompt.");
}

fn take_flag(args: &[String], flag: &str) -> (bool, Vec<String>) {
    let mut present = false;
    let kept = args
        .iter()
        .filter(|a| {
            if a.as_str() == flag {
                present = true;
                false
            } else {
                true
            }
        })
        .cloned()
        .collect();
    (present, kept)
}

fn build_client(gateway: &str, mainnet: bool) -> Client {
    if mainnet {
        Client::with_network(gateway.to_string(), Network::mainnet(), true)
    } else {
        Client::new(gateway.to_string())
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn read_seed(source: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    // Resolve the seed from a safe source so it need not sit in argv, where the process list and
    // shell history would expose it. @file reads it from a file, - reads a line from stdin, env:VAR
    // reads it from an environment variable, and a bare value is still accepted with a warning.
    let hex: Zeroizing<String> = Zeroizing::new(if let Some(var) = source.strip_prefix("env:") {
        std::env::var(var).map_err(|_| format!("the environment variable {var} is not set"))?
    } else if let Some(path) = source.strip_prefix('@') {
        std::fs::read_to_string(path).map_err(|e| format!("reading the seed file {path}: {e}"))?
    } else if source == "-" {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .map_err(|e| format!("reading the seed from stdin: {e}"))?;
        line
    } else {
        eprintln!(
            "warning: a seed on the command line is visible to other users through the process \
             list and shell history; prefer @file, - for stdin, or env:VAR"
        );
        source.to_string()
    });
    parse_seed(hex.trim())
}

fn parse_seed(hex: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err("a seed is sixty four hex characters".to_string());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "the seed is not hex")?;
        seed[i] = u8::from_str_radix(pair, 16).map_err(|_| "the seed is not hex")?;
    }
    Ok(seed)
}

fn parse_index(arg: Option<&String>) -> Result<u64, String> {
    match arg {
        Some(value) => value.parse().map_err(|_| "the index is not a number".to_string()),
        None => Ok(0),
    }
}
