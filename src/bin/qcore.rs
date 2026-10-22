// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use qcore::{
    account_address, account_public_key, generate_seed, mnemonic_from_seed, valid_address, Client,
    Network, Submit, TxStatus,
};
use qtv_wipe::Zeroizing;

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
    let phrase = mnemonic_from_seed(&seed);
    println!("seed    {}", seed_hex.as_str());
    println!("phrase  {}", *phrase);
    println!("address {}", account_address(&seed, 0));
    println!();
    println!("Keep the seed and the phrase secret. The phrase is the only backup of this key.");
    Ok(())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let (argv, args) = take_flag(args, "--insecure-argv");
    let seed = read_seed(
        args.first().ok_or("usage: qcore address <seed> [index]")?,
        argv,
    )?;
    let index = parse_index(args.get(1))?;
    println!("{}", account_address(&seed, index));
    Ok(())
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let (argv, args) = take_flag(args, "--insecure-argv");
    let seed = read_seed(
        args.first().ok_or("usage: qcore pubkey <seed> [index]")?,
        argv,
    )?;
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
    let (testnet, args) = take_flag(&args, "--testnet");
    let (acknowledged, args) = take_flag(&args, "--acknowledge-mainnet");
    let (argv, args) = take_flag(&args, "--insecure-argv");
    let (clock, args) = take_clock(&args)?;
    if args.len() < 3 {
        return Err(
            "usage: qcore register [--mainnet|--testnet] <gateway-url> <seed-hex> <max-fee>"
                .to_string(),
        );
    }
    let seed = read_seed(&args[1], argv)?;
    let max_fee = whole_arg::<u128>(&args[2], "the max fee is not a number")?;
    let client = build_client(&args[0], mainnet, acknowledged, testnet, clock)?;
    load_session(&client)?;
    let result = client.register(&seed, 0, max_fee);
    save_session(&client)?;
    let (_signed, outcome) = result?;
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
    let gateway = args
        .first()
        .ok_or("usage: qcore balance <gateway-url> <address>")?;
    let address = args
        .get(1)
        .ok_or("usage: qcore balance <gateway-url> <address>")?;
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
    let (testnet, args) = take_flag(&args, "--testnet");
    let (acknowledged, args) = take_flag(&args, "--acknowledge-mainnet");
    let (argv, args) = take_flag(&args, "--insecure-argv");
    let (clock, args) = take_clock(&args)?;
    if args.len() < 5 {
        return Err(
            "usage: qcore send [--mainnet|--testnet] <gateway-url> <seed-hex> <to> <amount> <max-fee>"
                .to_string(),
        );
    }
    let seed = read_seed(&args[1], argv)?;
    let to = &args[2];
    let amount = whole_arg::<u64>(&args[3], "the amount is not a number")?;
    let max_fee = whole_arg::<u128>(&args[4], "the max fee is not a number")?;
    let client = build_client(&args[0], mainnet, acknowledged, testnet, clock)?;
    load_session(&client)?;
    let result = client.transfer(&seed, 0, to, amount, max_fee);
    save_session(&client)?;
    let (_signed, outcome) = result?;
    match outcome {
        Submit::Accepted { state, tx_id } => {
            println!("submitted {tx_id}");
            println!("state     {state}");
            Ok(())
        }
        Submit::Rejected { reason, .. } => Err(format!("the node rejected the transfer: {reason}")),
    }
}

fn cmd_status(args: &[String]) -> Result<(), String> {
    let gateway = args
        .first()
        .ok_or("usage: qcore status <gateway-url> <tx-id>")?;
    let tx_id = args
        .get(1)
        .ok_or("usage: qcore status <gateway-url> <tx-id>")?;
    match Client::new(gateway.clone()).transaction(tx_id)? {
        TxStatus::Finalised {
            height,
            block: Some(block),
        } => println!("finalised at height {height} in block {block}"),
        TxStatus::Finalised {
            height,
            block: None,
        } => println!("finalised at height {height}"),
        TxStatus::Unverified { height, .. } => {
            return Err(format!(
                "UNVERIFIED, the gateway alone reports it finalised at height {height}; no trusted validator roster checked it"
            ))
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
    println!(
        "  qcore address <seed-hex> [index]                      the address for a seed and index"
    );
    println!("  qcore pubkey <seed-hex> [index]                       the scheme, public key, and address, for genesis");
    println!(
        "  qcore info <gateway-url>                              the chain id, height, and fee"
    );
    println!("  qcore register [--testnet|--mainnet] <gateway-url> <seed-hex> <max-fee>     register a funded account's key so it can send");
    println!(
        "  qcore balance <gateway-url> <address>                 an account balance and nonce"
    );
    println!("  qcore send [--testnet|--mainnet] <gateway-url> <seed-hex> <to> <amount> <max-fee>   sign and submit a transfer");
    println!("  qcore status <gateway-url> <tx-id>                    where a transaction is");
    println!();
    println!("A <seed> can be the hex directly, @file to read it from a file, - to read it from");
    println!("stdin, or env:VAR to read it from an environment variable. Prefer the last three so");
    println!("the seed never appears in the process list or your shell history. A seed typed");
    println!("directly is refused unless --insecure-argv is given.");
    println!();
    println!(
        "Pass --testnet or --mainnet on a signing command to bind the client to that network;"
    );
    println!(
        "--mainnet also needs --acknowledge-mainnet, since the transaction moves real value. It refuses"
    );
    println!(
        "to sign if the gateway does not serve the chosen network, and refuses to sign for either"
    );
    println!("public network when neither flag is given.");
    println!();
    println!(
        "A signing command keeps its nonces in ~/.qcore/session.json, or the file QCORE_SESSION"
    );
    println!(
        "names, so a later run never signs a second transaction at a nonce already used. On a"
    );
    println!("private chain pass --genesis-time <unix-secs> --block-rate <blocks-per-sec> so the");
    println!("validity deadline is bounded by the chain clock rather than the gateway's word.");
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

fn take_value(args: &[String], flag: &str) -> Result<(Option<u64>, Vec<String>), String> {
    let mut value = None;
    let mut kept = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            let text = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
            value = Some(whole_arg::<u64>(text, &format!("{flag} is not a number"))?);
        } else {
            kept.push(arg.clone());
        }
    }
    Ok((value, kept))
}

type Clock = Option<(u64, u64)>;

fn take_clock(args: &[String]) -> Result<(Clock, Vec<String>), String> {
    let (genesis, args) = take_value(args, "--genesis-time")?;
    let (rate, args) = take_value(&args, "--block-rate")?;
    match (genesis, rate) {
        (Some(genesis), Some(rate)) => Ok((Some((genesis, rate)), args)),
        (None, None) => Ok((None, args)),
        _ => Err("--genesis-time and --block-rate go together".to_string()),
    }
}

fn session_path() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("QCORE_SESSION") {
        return Some(path.into());
    }
    std::env::var_os("HOME").map(|home| {
        std::path::Path::new(&home)
            .join(".qcore")
            .join("session.json")
    })
}

fn load_session(client: &Client) -> Result<(), String> {
    let Some(path) = session_path() else {
        return Ok(());
    };
    match std::fs::read_to_string(&path) {
        Ok(state) => client.restore_session(&state).map_err(|e| {
            format!(
                "the saved signing session {} is unreadable: {e}",
                path.display()
            )
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "reading the signing session {}: {e}",
            path.display()
        )),
    }
}

fn save_session(client: &Client) -> Result<(), String> {
    let Some(path) = session_path() else {
        return Err("no HOME or QCORE_SESSION to keep the signing session in, refusing to forget the nonces this run signed".to_string());
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let temp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|e| format!("writing the signing session {}: {e}", temp.display()))?;
    use std::io::Write;
    file.write_all(client.save_session().as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|e| format!("writing the signing session {}: {e}", temp.display()))?;
    std::fs::rename(&temp, &path)
        .map_err(|e| format!("keeping the signing session {}: {e}", path.display()))
}

fn build_client(
    gateway: &str,
    mainnet: bool,
    acknowledged: bool,
    testnet: bool,
    clock: Clock,
) -> Result<Client, String> {
    if mainnet && !acknowledged {
        return Err(
            "--mainnet moves real value; pass --acknowledge-mainnet as well to sign for it"
                .to_string(),
        );
    }
    let client = if mainnet {
        Client::with_network(gateway.to_string(), Network::mainnet(), true)
    } else if testnet {
        Client::with_network(gateway.to_string(), Network::testnet(), false)
    } else {
        Client::new(gateway.to_string())
    };
    Ok(match clock {
        Some((genesis, rate)) => client.with_chain_clock(genesis, rate),
        None => client,
    })
}

fn whole_arg<T: TryFrom<u128>>(text: &str, message: &str) -> Result<T, String> {
    qcore::whole_number(text)
        .and_then(|n| T::try_from(n).ok())
        .ok_or_else(|| message.to_string())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const SEED_BUFFER: usize = 64 * 1024;

fn read_seed(source: &str, insecure_argv: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    let mut buffer = Zeroizing::new([0u8; SEED_BUFFER]);
    let filled = if let Some(var) = source.strip_prefix("env:") {
        let value = Zeroizing::new(
            std::env::var(var).map_err(|_| format!("the environment variable {var} is not set"))?,
        );
        copy_into(&mut buffer[..], value.as_bytes())?
    } else if let Some(path) = source.strip_prefix('@') {
        let mut file = open_seed_file(path)?;
        read_into(&mut file, &mut buffer[..])
            .map_err(|e| format!("reading the seed file {path}: {e}"))?
    } else if source == "-" {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        read_into(&mut lock, &mut buffer[..])
            .map_err(|e| format!("reading the seed from stdin: {e}"))?
    } else {
        if !insecure_argv {
            return Err(
                "a seed on the command line is visible to other users through the process list \
                 and shell history; pass it as @file, - for stdin, or env:VAR, or repeat the \
                 command with --insecure-argv"
                    .to_string(),
            );
        }
        copy_into(&mut buffer[..], source.as_bytes())?
    };
    parse_seed_bytes(&buffer[..filled])
}

fn copy_into(buffer: &mut [u8], bytes: &[u8]) -> Result<usize, String> {
    let slot = buffer
        .get_mut(..bytes.len())
        .ok_or("the seed source is too long")?;
    slot.copy_from_slice(bytes);
    Ok(bytes.len())
}

fn read_into(reader: &mut impl std::io::Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() / 2 {
        let n = reader.read(&mut buffer[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
        if buffer[..filled].contains(&b'\n') {
            break;
        }
    }
    Ok(filled)
}

fn open_seed_file(path: &str) -> Result<std::fs::File, String> {
    let file =
        std::fs::File::open(path).map_err(|e| format!("opening the seed file {path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = file
            .metadata()
            .map_err(|e| format!("inspecting the seed file {path}: {e}"))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "the seed file {path} is readable by group or others, restrict it with chmod 600 before use"
            ));
        }
    }
    Ok(file)
}

fn parse_seed_bytes(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    let hex = raw.trim_ascii();
    if hex.len() != 64 || !hex.iter().all(|b| b.is_ascii_hexdigit()) {
        return Err("a seed is sixty four hex characters".to_string());
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    for (i, pair) in hex.chunks(2).enumerate() {
        let nibble = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
        seed[i] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    Ok(seed)
}

fn parse_index(arg: Option<&String>) -> Result<u64, String> {
    match arg {
        Some(value) => whole_arg::<u64>(value, "the index is not a number"),
        None => Ok(0),
    }
}

#[cfg(test)]
mod seed_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_group_readable_seed_file_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("qcore_seed_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("seed");
        std::fs::write(&path, "ab".repeat(32)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let shared = read_seed(&format!("@{}", path.display()), false);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let private = read_seed(&format!("@{}", path.display()), false);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(shared.is_err());
        assert!(private.is_ok());
    }

    #[test]
    fn a_seed_with_a_sign_character_is_refused() {
        assert!(parse_seed_bytes(format!("+a{}", "b".repeat(62)).as_bytes()).is_err());
        assert!(whole_arg::<u64>("+5", "x").is_err());
        assert!(whole_arg::<u64>("18446744073709551616", "x").is_err());
        assert_eq!(whole_arg::<u64>("5", "x"), Ok(5));
        assert!(parse_seed_bytes("ab".repeat(32).as_bytes()).is_ok());
    }
}
