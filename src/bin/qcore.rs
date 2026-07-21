use qcore::{
    account_address, account_public_key, generate_seed, mnemonic_from_seed, valid_address, Client,
    Submit, TxStatus,
};

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
    println!("seed    {}", to_hex(&seed));
    println!("phrase  {}", mnemonic_from_seed(&seed));
    println!("address {}", account_address(&seed, 0));
    println!();
    println!("Keep the seed and the phrase secret. The phrase is the only backup of this key.");
    Ok(())
}

fn cmd_address(args: &[String]) -> Result<(), String> {
    let seed = parse_seed(args.first().ok_or("usage: qcore address <seed-hex> [index]")?)?;
    let index = parse_index(args.get(1))?;
    println!("{}", account_address(&seed, index));
    Ok(())
}

fn cmd_pubkey(args: &[String]) -> Result<(), String> {
    let seed = parse_seed(args.first().ok_or("usage: qcore pubkey <seed-hex> [index]")?)?;
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
    if args.len() < 2 {
        return Err("usage: qcore register <gateway-url> <seed-hex>".to_string());
    }
    let seed = parse_seed(&args[1])?;
    let client = Client::new(args[0].clone());
    let info = client.node_info()?;
    let (_signed, outcome) = client.register(&seed, 0, info.transfer_fee)?;
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
        return Err("the address is not a q1 address".to_string());
    }
    let account = Client::new(gateway.clone()).account(address)?;
    println!("address {}", account.address);
    println!("balance {}", account.balance);
    println!("nonce   {}", account.nonce);
    Ok(())
}

fn cmd_send(args: &[String]) -> Result<(), String> {
    if args.len() < 5 {
        return Err(
            "usage: qcore send <gateway-url> <seed-hex> <to> <amount> <max-fee>".to_string(),
        );
    }
    let seed = parse_seed(&args[1])?;
    let to = &args[2];
    let amount: u64 = args[3].parse().map_err(|_| "the amount is not a number")?;
    let max_fee: u128 = args[4].parse().map_err(|_| "the max fee is not a number")?;
    let (_signed, outcome) = Client::new(args[0].clone()).transfer(&seed, 0, to, amount, max_fee)?;
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
    println!("  qcore register <gateway-url> <seed-hex>               register a funded account's key so it can send");
    println!("  qcore balance <gateway-url> <address>                 an account balance and nonce");
    println!("  qcore send <gateway-url> <seed-hex> <to> <amount> <max-fee>   sign and submit a transfer");
    println!("  qcore status <gateway-url> <tx-id>                    where a transaction is");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_seed(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err("a seed is sixty four hex characters".to_string());
    }
    let mut seed = [0u8; 32];
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
