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
        scheme: field_u64(&v, "scheme")? as u8,
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

        /// Read node info for the fee, read the sender's nonce, sign the transfer, and
        pub fn transfer(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            to: &str,
            amount: u64,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let signed = sign_transfer(seed, index, to, amount, account.nonce, info.transfer_fee);
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }

        /// Read the fee and the sender's nonce, sign a call to a target with the given meter
        pub fn call(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            meter_limit: u64,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let signed = sign_call(seed, index, target, args, account.nonce, meter_limit, info.transfer_fee);
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
}
