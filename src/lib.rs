//! The Quantova client core.

pub mod json;

#[cfg(feature = "client")]
mod http;

use json::{object, to_hex, Json};
use qtv_account::derive;
use qtv_codec::{to_bytes, Encoder};
use qtv_tx::{sign, Body, Call};

/// The length of a master seed in bytes.
pub const SEED_LEN: usize = 32;

/// The meter limit a native transfer needs. The fixed transfer program spends this
pub const NATIVE_TRANSFER_METER: u64 = 1_210;

/// The derived address of an account under a master seed and an index, the same
pub fn account_address(seed: &[u8; SEED_LEN], index: u64) -> String {
    derive(seed, index).address()
}

/// The public key of an account under a master seed and an index, the module lattice key the address
pub fn account_public_key(seed: &[u8; SEED_LEN], index: u64) -> Vec<u8> {
    derive(seed, index).public_key().to_vec()
}

/// The reserved address an account registers its public key to. A fresh account funded by a transfer
pub fn key_register_address() -> String {
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/key/register"))
        .expect("a full hash reaches the address floor")
}

/// A signed transfer ready to submit: its canonical bytes, its id, and the sender it
#[derive(Debug, Clone)]
pub struct SignedTransfer {
    pub from: String,
    pub tx_id: String,
    pub tx_bytes: Vec<u8>,
}

/// Build and sign a call to a target with its arguments already encoded. A native transfer
pub fn sign_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
) -> SignedTransfer {
    let sender = derive(seed, index);
    let call = Call::new(target.to_string(), args);
    let body = Body::new(sender.address(), nonce, meter_limit, fee, call);
    let wrapper = sign(&sender, &body);
    SignedTransfer {
        from: sender.address(),
        tx_id: wrapper.id(),
        tx_bytes: to_bytes(&wrapper),
    }
}

/// Build and sign a native transfer. The amount is encoded into the call the way the node
pub fn sign_transfer(
    seed: &[u8; SEED_LEN],
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
) -> SignedTransfer {
    let mut encoder = Encoder::new();
    encoder.put_u64(amount);
    sign_call(seed, index, to, encoder.into_bytes(), nonce, NATIVE_TRANSFER_METER, fee)
}

/// Build and sign a key registration. The account's public key is the argument, the target is the
pub fn sign_register(seed: &[u8; SEED_LEN], index: u64, nonce: u64, fee: u128) -> SignedTransfer {
    let public_key = account_public_key(seed, index);
    sign_call(
        seed,
        index,
        &key_register_address(),
        public_key,
        nonce,
        NATIVE_TRANSFER_METER,
        fee,
    )
}

// The wire encoders and decoders. A binding calls these so the host never builds a
// request body or reads a response field by name.

/// The request body for submit, the transaction as hex.
pub fn submit_body(tx_bytes: &[u8]) -> String {
    object(vec![("tx", Json::str(to_hex(tx_bytes)))]).render()
}

/// The request body for get account.
pub fn account_body(address: &str) -> String {
    object(vec![("address", Json::str(address))]).render()
}

/// The request body for get transaction.
pub fn transaction_body(tx_id: &str) -> String {
    object(vec![("tx_id", Json::str(tx_id))]).render()
}

/// The request body for get block by height.
pub fn block_by_height_body(height: u64) -> String {
    object(vec![("height", Json::Int(height))]).render()
}

/// What node info reports.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub chain_id: String,
    pub genesis_hash: String,
    pub head_height: u64,
    pub denomination: String,
    pub transfer_fee: u128,
    pub version: String,
}

/// An account's on chain record.
#[derive(Debug, Clone)]
pub struct Account {
    pub address: String,
    pub nonce: u64,
    pub balance: u128,
    pub scheme: u8,
    pub has_key: bool,
}

/// The outcome of a submission.
#[derive(Debug, Clone)]
pub enum Submit {
    Accepted { state: String, tx_id: String },
    Rejected { reason: String, expected: Option<u64>, got: Option<u64> },
}

/// Where a transaction is in its life.
#[derive(Debug, Clone)]
pub enum TxStatus {
    Finalised { height: u64, block: String },
    Pending,
    Unknown,
}

fn field_str(v: &Json, key: &str) -> Result<String, String> {
    v.get(key)
        .and_then(Json::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| format!("the response is missing a string {key}"))
}

fn field_u64(v: &Json, key: &str) -> Result<u64, String> {
    v.get(key)
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("the response is missing a number {key}"))
}

fn field_u128(v: &Json, key: &str) -> Result<u128, String> {
    field_str(v, key)?
        .parse::<u128>()
        .map_err(|_| format!("the {key} field is not a number string"))
}

fn field_u8(v: &Json, key: &str) -> Result<u8, String> {
    let n = field_u64(v, key)?;
    u8::try_from(n).map_err(|_| format!("the {key} field is out of range for a byte"))
}

/// Whether an address parses as a Quantova q1 address. A caller checks a recipient or a
pub fn valid_address(address: &str) -> bool {
    qtv_idfmt::parse_address(address).is_ok()
}

/// The standard English word list, one word per line.
fn word_list() -> Vec<&'static str> {
    include_str!("english.txt").lines().collect()
}

/// The recovery phrase for a master seed. The phrase carries the thirty two seed bytes and an
pub fn mnemonic_from_seed(seed: &[u8; SEED_LEN]) -> String {
    let words = word_list();
    let checksum = qtv_crypto::sha3::sha3_256(seed)[0];
    let mut bits: Vec<u8> = Vec::with_capacity(SEED_LEN * 8 + 8);
    for &byte in seed.iter() {
        for shift in (0..8).rev() {
            bits.push((byte >> shift) & 1);
        }
    }
    for shift in (0..8).rev() {
        bits.push((checksum >> shift) & 1);
    }
    bits.chunks(11)
        .map(|chunk| {
            let index = chunk.iter().fold(0usize, |acc, &bit| (acc << 1) | bit as usize);
            words[index]
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The master seed a recovery phrase carries, or an error if the phrase is the wrong length, has
pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; SEED_LEN], String> {
    let words = word_list();
    let entered: Vec<&str> = phrase.split_whitespace().collect();
    if entered.len() != 24 {
        return Err("a recovery phrase is twenty four words".to_string());
    }
    let mut bits: Vec<u8> = Vec::with_capacity(24 * 11);
    for word in &entered {
        let index = words
            .iter()
            .position(|candidate| candidate == word)
            .ok_or("a word in the phrase is not in the word list")?;
        for shift in (0..11).rev() {
            bits.push(((index >> shift) & 1) as u8);
        }
    }
    let mut seed = [0u8; SEED_LEN];
    for (i, byte) in seed.iter_mut().enumerate() {
        *byte = bits[i * 8..i * 8 + 8].iter().fold(0u8, |acc, &bit| (acc << 1) | bit);
    }
    let checksum = bits[SEED_LEN * 8..SEED_LEN * 8 + 8]
        .iter()
        .fold(0u8, |acc, &bit| (acc << 1) | bit);
    if checksum != qtv_crypto::sha3::sha3_256(&seed)[0] {
        return Err("the recovery phrase checksum does not match, check for a typo".to_string());
    }
    Ok(seed)
}

/// Parse a node info response.
pub fn parse_node_info(response: &str) -> Result<NodeInfo, String> {
    let v = json::parse(response)?;
    let fee = v.get("fee").ok_or("no fee in node info")?;
    Ok(NodeInfo {
        chain_id: field_str(&v, "chain_id")?,
        genesis_hash: field_str(&v, "genesis_hash")?,
        head_height: field_u64(&v, "head_height")?,
        denomination: field_str(&v, "denomination")?,
        transfer_fee: field_u128(fee, "transfer_quon")?,
        version: field_str(&v, "version")?,
    })
}

/// Parse an account response.
pub fn parse_account(response: &str) -> Result<Account, String> {
    let v = json::parse(response)?;
    Ok(Account {
        address: field_str(&v, "address")?,
        nonce: field_u64(&v, "nonce")?,
        balance: field_u128(&v, "balance")?,
        scheme: field_u8(&v, "scheme")?,
        has_key: v.get("has_key").and_then(Json::as_bool).unwrap_or(false),
    })
}

/// Parse a submit response.
pub fn parse_submit(response: &str) -> Result<Submit, String> {
    let v = json::parse(response)?;
    match field_str(&v, "verdict")?.as_str() {
        "accepted" => Ok(Submit::Accepted {
            state: field_str(&v, "state")?,
            tx_id: field_str(&v, "tx_id")?,
        }),
        "rejected" => Ok(Submit::Rejected {
            reason: field_str(&v, "reason")?,
            expected: v.get("expected").and_then(Json::as_u64),
            got: v.get("got").and_then(Json::as_u64),
        }),
        other => Err(format!("unknown verdict {other}")),
    }
}

/// Parse a get transaction response.
pub fn parse_transaction(response: &str) -> Result<TxStatus, String> {
    let v = json::parse(response)?;
    match field_str(&v, "status")?.as_str() {
        "finalised" => Ok(TxStatus::Finalised {
            height: field_u64(&v, "height")?,
            block: field_str(&v, "block")?,
        }),
        "pending" => Ok(TxStatus::Pending),
        "unknown" => Ok(TxStatus::Unknown),
        other => Err(format!("unknown status {other}")),
    }
}

/// Generate a fresh thirty two byte master seed from the operating system's cryptographic random
#[cfg(feature = "client")]
pub fn generate_seed() -> Result<[u8; SEED_LEN], String> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut file =
            std::fs::File::open("/dev/urandom").map_err(|e| format!("open the random source: {e}"))?;
        let mut seed = [0u8; SEED_LEN];
        file.read_exact(&mut seed)
            .map_err(|e| format!("read the random source: {e}"))?;
        Ok(seed)
    }
    #[cfg(not(unix))]
    {
        Err("generate_seed reads /dev/urandom and runs on unix only, so on another platform draw \
             thirty two bytes from the platform cryptographic random source and pass them in"
            .to_string())
    }
}

/// The native client under the `client` feature.
#[cfg(feature = "client")]
pub use client::Client;

#[cfg(feature = "client")]
mod client {
    use super::*;

    /// A client bound to a gateway base url, `http://host:port`.
    pub struct Client {
        base: String,
    }

    impl Client {
        pub fn new(base: impl Into<String>) -> Client {
            Client { base: base.into() }
        }

        fn rpc(&self, method: &str, body: String) -> Result<String, String> {
            let (status, text) = http::post(&self.base, &format!("/v1/{method}"), &body)?;
            if status == 200 {
                Ok(text)
            } else {
                Err(format!("the gateway returned {status}: {text}"))
            }
        }

        pub fn node_info(&self) -> Result<NodeInfo, String> {
            parse_node_info(&self.rpc("node_info", "{}".to_string())?)
        }

        pub fn account(&self, address: &str) -> Result<Account, String> {
            parse_account(&self.rpc("get_account", account_body(address))?)
        }

        pub fn submit(&self, tx_bytes: &[u8]) -> Result<Submit, String> {
            parse_submit(&self.rpc("submit_transaction", submit_body(tx_bytes))?)
        }

        pub fn transaction(&self, tx_id: &str) -> Result<TxStatus, String> {
            parse_transaction(&self.rpc("get_transaction", transaction_body(tx_id))?)
        }

        /// Read node info for the fee, read the sender's nonce, sign the transfer, and submit it.
        pub fn transfer(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            to: &str,
            amount: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(to) {
                return Err("the recipient is not a q1 address".to_string());
            }
            let info = self.node_info()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let signed = sign_transfer(seed, index, to, amount, account.nonce, info.transfer_fee);
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }

        /// Read the fee and the sender's nonce, sign a call to a target with the given meter limit and
        pub fn call(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(target) {
                return Err("the target is not a q1 address".to_string());
            }
            let info = self.node_info()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let signed = sign_call(seed, index, target, args, account.nonce, meter_limit, info.transfer_fee);
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }

        /// Register this account's public key on the chain, so an account funded by a transfer, which
        pub fn register(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let signed = sign_register(seed, index, account.nonce, info.transfer_fee);
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transfer_is_a_call_that_encodes_the_amount() {
        let seed = [7u8; SEED_LEN];
        let to = account_address(&seed, 0);
        let transfer = sign_transfer(&seed, 0, &to, 1000, 3, 500);
        let mut encoder = Encoder::new();
        encoder.put_u64(1000);
        let call = sign_call(&seed, 0, &to, encoder.into_bytes(), 3, NATIVE_TRANSFER_METER, 500);
        assert_eq!(transfer.tx_bytes, call.tx_bytes);
        assert_eq!(transfer.tx_id, call.tx_id);
    }

    #[test]
    fn a_deeply_nested_response_is_refused_not_crashed() {
        let deep = "[".repeat(100_000) + &"]".repeat(100_000);
        assert!(crate::json::parse(&deep).is_err());
        let deep_obj = "{\"a\":".repeat(100_000);
        assert!(crate::json::parse(&deep_obj).is_err());
    }

    #[test]
    fn bad_hex_is_a_clean_error_that_carries_no_input() {
        assert!(crate::json::from_hex("abc").is_err());
        let err = crate::json::from_hex("zz").unwrap_err();
        assert!(!err.contains('z'));
    }

    #[test]
    fn valid_address_accepts_a_derived_address_and_rejects_junk() {
        let address = account_address(&[7u8; SEED_LEN], 0);
        assert!(valid_address(&address));
        assert!(!valid_address("not an address"));
        assert!(!valid_address(""));
    }

    #[test]
    fn a_repeated_key_reads_the_last_value_like_a_browser() {
        let v = crate::json::parse("{\"n\":\"1\",\"n\":\"9\"}").unwrap();
        assert_eq!(v.get("n").and_then(crate::json::Json::as_str), Some("9"));
    }

    #[test]
    fn a_seed_round_trips_through_its_recovery_phrase() {
        let seed = [7u8; SEED_LEN];
        let phrase = mnemonic_from_seed(&seed);
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(seed_from_mnemonic(&phrase).unwrap(), seed);
        // the phrase recovers the account the seed signs from
        assert_eq!(
            account_address(&seed_from_mnemonic(&phrase).unwrap(), 0),
            account_address(&seed, 0)
        );
        // a mistyped word is refused by the checksum
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words[0] = if words[0] == "abandon" { "ability" } else { "abandon" };
        assert!(seed_from_mnemonic(&words.join(" ")).is_err());
    }
}
