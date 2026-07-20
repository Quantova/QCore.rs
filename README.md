# QCore.rs

The Quantova post quantum client core, written in Rust. It is the one place a Quantova client does the four things it has to get exactly right. It derives a post quantum key. It builds a transaction. It signs that transaction with the post quantum scheme. It speaks the Quantova gateway wire. QCore.js and QCore.py are generated over this same core, so a signature is written once in Rust and never rewritten in another language. A second implementation of the signing would be a second chance to be wrong with a user's money, so there is only ever the one.

One core with one binding for each language. QCore.rs is this Rust core. QCore.js is the JavaScript and WebAssembly binding over it. QCore.py is the Python binding over it. All three derive the same address from the same seed and sign the same body to the same bytes, because they are the one core rather than three copies of it.

## What this library is for

Any program that holds a Quantova account, reads the chain, and sends signed transactions. A wallet, a block explorer, a faucet, a trading bot, a backend service, or a command line tool. The program makes whatever network calls it prefers and QCore does the cryptography and the wire, so the program never hand builds a signature or a request body and never has to understand the byte layout of a transaction.

## The post quantum cryptography it handles

Quantova is post quantum from the ground. There is no elliptic curve anywhere in it, no secp256k1, no ECDSA, no Ethereum address, and no Substrate envelope. Every primitive below is Quantova's own from scratch implementation in the Q Crypto library, carrying no third party cryptography dependency, and QCore builds directly on the chain's own account and transaction code so a client and the node agree byte for byte.

1. Key derivation. A wallet holds one master seed of thirty two bytes. QCore grows a per account seed from it with SHAKE256 over the master seed, the scheme byte, and the account index, then derives a module lattice key pair from that seed. The node runs the identical derivation, so the account a key signs from is the account that holds the funds.

2. The signing scheme. The default is the module lattice signature ML-DSA-65 as standardised in FIPS 204, carried on the wire as scheme one. The hash based signature SLH-DSA as standardised in FIPS 205 is scheme two. Signing is deterministic, so one transaction body always signs to one exact run of bytes, which makes a signed transaction reproducible and testable.

3. The address. A Quantova address is the Bech32m q1 string that renders the SHA3 256 hash of the scheme byte together with the whole module lattice public key of one thousand nine hundred fifty two bytes. The entire public key is bound into the address. Nothing is truncated to a twenty byte hash and there is no key recovery from a signature, so one address names exactly one post quantum key.

4. The transaction. A transaction body carries the sender, the nonce, the meter limit, the fee, and the call. The bytes a signature stands over are the SHA3 256 hash of the canonical body followed by a fixed Quantova transaction domain tag, so a transaction signature can never be replayed as another kind of signed message. QCore assembles the body, signs the digest with the account's post quantum key, and returns the canonical wrapper bytes and the transaction id ready for the gateway.

## How it is customised to Quantova and inherits nothing from the industry

Quantova shares no wire, no address, and no unit with any other chain, and QCore speaks only Quantova. The address is a q1 Bech32m string over a full post quantum key, never a hex twenty byte address and never an SS58 string. Money is counted in Quon, the smallest unit, at one million Quon to one QTOV, and it always crosses the wire as a decimal string so a JavaScript number never rounds a balance. The wire is the Quantova gateway, an HTTP POST to a named method under a version prefix with a flat JSON body, not Ethereum JSON RPC and not a Substrate WebSocket. The transaction encoding is Quantova's own canonical codec, not RLP and not SCALE. The signatures come from Q Crypto, Quantova's own implementation of the lattice and hash standards written from scratch, not a borrowed crate. QCore does not translate to or from any older format because there is nothing older to translate.

## Creating a wallet

Under the client feature the core generates a fresh master seed from the operating system random
source, so a wallet creates a new key with one call. The recovery phrase is the only backup and stays
on the device.

```rust
let seed = qcore::generate_seed()?;
let phrase = qcore::mnemonic_from_seed(&seed);
```

## Using it from Rust

The client feature adds a small HTTP transport over the standard library for native callers and for proving the core against a running gateway. The example below reads the fee and the nonce, signs a transfer inside the core, and submits it. The caller passes the highest fee it will accept and the core refuses to sign a fee the gateway reports above it, so a gateway cannot inflate the fee and drain the account. Over this transport the client speaks plaintext only to a loopback node, since without transport security a gateway across an untrusted network could rewrite the fee and the nonce, so reach a remote gateway through a tunnel that ends on loopback.

```rust
use qcore::{Client, account_address, TxStatus};

let client = Client::new("http://127.0.0.1:8645");
let seed = [11u8; 32];
let to = account_address(&seed, 1);

let info = client.node_info()?;
let (signed, outcome) = client.transfer(&seed, 0, &to, 1000, info.transfer_fee)?;
let status = client.transaction(&signed.tx_id)?;
```

## Building

```
cargo build --features client
cargo test --features client
```

## Terminal client

The client feature also builds a small terminal client, qcore, over the same core, so a person can
create a wallet, read the chain, and send a transfer from the shell. It signs exactly as a wallet
does and never hand rolls a signature.

```
qcore new                                             create a wallet, seed, phrase, and address
qcore address <seed-hex> [index]                      the address for a seed and index
qcore info <gateway-url>                              the chain id, height, and fee
qcore register <gateway-url> <seed-hex>               register a funded account's key so it can send
qcore balance <gateway-url> <address>                 an account balance and nonce
qcore send <gateway-url> <seed-hex> <to> <amount> <max-fee>   sign and submit a transfer
qcore status <gateway-url> <tx-id>                    where a transaction is
```

## Ownership and license

QCore.rs is built and owned by Quantova Inc and is the reference core that QCore.js and QCore.py are generated over. It carries none of the industry stack and inherits nothing from it. Everything from the key derivation to the wire is Quantova's own. It is released under the Apache 2.0 and MIT licenses so any wallet, explorer, or service may build on it, and the copyright stays with Quantova Inc.
