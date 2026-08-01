// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub mod contract;
pub mod json;

#[cfg(feature = "client")]
mod http;

use json::{object, to_hex, Json};
use qtv_account::derive;
use qtv_codec::{to_bytes, Encoder};
use qtv_tx::{sign, Body, Call};
use zeroize::Zeroizing;

pub use qtv_tx::{
    chain_id_from_name, LOCAL_CHAIN_ID, LOCAL_CHAIN_NAME, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME,
    TESTNET_CHAIN_ID, TESTNET_CHAIN_NAME,
};

pub const SEED_LEN: usize = 32;

pub const ADDRESS_PAYLOAD_LEN: usize = 32;

pub const NATIVE_TRANSFER_METER: u64 = 1_210;

pub const DENOMINATION: &str = "Quon";

pub const DECIMALS: u8 = 6;

#[derive(Debug, Clone)]
pub struct Network {
    pub name: String,
    pub chain_id: Option<String>,
    pub rpc_url: Option<String>,
    pub explorer_url: Option<String>,
    pub denomination: String,
    pub decimals: u8,
    pub is_mainnet: bool,
}

impl Network {
    pub fn testnet() -> Network {
        Network {
            name: "testnet".to_string(),
            chain_id: Some("Q-test-net-1".to_string()),
            rpc_url: Some("https://rpc-testnet.quantova.org".to_string()),
            explorer_url: Some("https://qvmscan.io".to_string()),
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: false,
        }
    }

    pub fn mainnet() -> Network {
        Network {
            name: "mainnet".to_string(),
            chain_id: Some("Q-main-net-1".to_string()),
            rpc_url: None,
            explorer_url: Some("https://qvmscan.io".to_string()),
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: true,
        }
    }

    pub fn for_url(base: impl Into<String>) -> Network {
        Network {
            name: "custom".to_string(),
            chain_id: None,
            rpc_url: Some(base.into()),
            explorer_url: None,
            denomination: DENOMINATION.to_string(),
            decimals: DECIMALS,
            is_mainnet: false,
        }
    }
}

pub fn account_address(seed: &[u8; SEED_LEN], index: u64) -> String {
    derive(seed, index).address()
}

pub fn account_public_key(seed: &[u8; SEED_LEN], index: u64) -> Vec<u8> {
    derive(seed, index).public_key().to_vec()
}

pub fn key_register_address() -> String {
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/key/register"))
        .expect("a full hash reaches the address floor")
}

pub fn vm_deploy_address() -> String {
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(b"qtv/vm/deploy"))
        .expect("a full hash reaches the address floor")
}

pub fn contract_address(deployer: &str, nonce: u64) -> Option<String> {
    let payload = qtv_idfmt::parse_address(deployer).ok()?;
    if payload.len() != 32 {
        return None;
    }
    let mut input = Vec::with_capacity(16 + 32 + 8);
    input.extend_from_slice(b"qtv/vm/contract/");
    input.extend_from_slice(&payload);
    input.extend_from_slice(&nonce.to_le_bytes());
    qtv_idfmt::render_address(&qtv_crypto::sha3::sha3_256(&input)).ok()
}

#[derive(Debug, Clone)]
pub struct SignedTransfer {
    pub from: String,
    pub tx_id: String,
    pub tx_bytes: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn sign_payable_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    value: u64,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
) -> Result<SignedTransfer, String> {
    if !valid_address(target) {
        return Err("the target is not a Q1 address".to_string());
    }
    let sender = derive(seed, index);
    let call = Call::new(target.to_string(), args);
    let body = Body::with_context(
        sender.address(),
        nonce,
        meter_limit,
        fee,
        call,
        value,
        chain_id,
    );
    let wrapper = sign(&sender, &body);
    Ok(SignedTransfer {
        from: sender.address(),
        tx_id: wrapper.id(),
        tx_bytes: to_bytes(&wrapper),
    })
}

#[allow(clippy::too_many_arguments)]
pub fn sign_call(
    seed: &[u8; SEED_LEN],
    index: u64,
    target: &str,
    args: Vec<u8>,
    nonce: u64,
    meter_limit: u64,
    fee: u128,
    chain_id: u64,
) -> Result<SignedTransfer, String> {
    sign_payable_call(seed, index, target, args, 0, nonce, meter_limit, fee, chain_id)
}

pub fn sign_transfer(
    seed: &[u8; SEED_LEN],
    index: u64,
    to: &str,
    amount: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
) -> Result<SignedTransfer, String> {
    let mut encoder = Encoder::new();
    encoder.put_u64(amount);
    sign_call(seed, index, to, encoder.into_bytes(), nonce, NATIVE_TRANSFER_METER, fee, chain_id)
}

pub fn sign_register(
    seed: &[u8; SEED_LEN],
    index: u64,
    nonce: u64,
    fee: u128,
    chain_id: u64,
) -> Result<SignedTransfer, String> {
    let public_key = account_public_key(seed, index);
    sign_call(
        seed,
        index,
        &key_register_address(),
        public_key,
        nonce,
        NATIVE_TRANSFER_METER,
        fee,
        chain_id,
    )
}

pub fn submit_body(tx_bytes: &[u8]) -> String {
    object(vec![("tx", Json::str(to_hex(tx_bytes)))]).render()
}

pub fn account_body(address: &str) -> String {
    object(vec![("address", Json::str(address))]).render()
}

pub fn transaction_body(tx_id: &str) -> String {
    object(vec![("tx_id", Json::str(tx_id))]).render()
}

pub fn block_by_height_body(height: u64) -> String {
    object(vec![("height", Json::Int(height))]).render()
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub chain_id: String,
    pub genesis_hash: String,
    pub head_height: u64,
    pub denomination: String,
    pub transfer_fee: u128,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub address: String,
    pub nonce: u64,
    pub balance: u128,
    pub scheme: u8,
    pub has_key: bool,
}

#[derive(Debug, Clone)]
pub enum Submit {
    Accepted { state: String, tx_id: String },
    Rejected { reason: String, expected: Option<u64>, got: Option<u64> },
}

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

pub fn valid_address(address: &str) -> bool {
    matches!(qtv_idfmt::parse_address(address), Ok(payload) if payload.len() == ADDRESS_PAYLOAD_LEN)
}

fn word_list() -> Vec<&'static str> {
    include_str!("english.txt").lines().collect()
}

pub fn mnemonic_from_seed(seed: &[u8; SEED_LEN]) -> String {
    let words = word_list();
    let checksum = qtv_crypto::sha3::sha3_256(seed)[0];
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SEED_LEN * 8 + 8));
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

pub fn seed_from_mnemonic(phrase: &str) -> Result<[u8; SEED_LEN], String> {
    let words = word_list();
    let entered: Vec<&str> = phrase.split_whitespace().collect();
    if entered.len() != 24 {
        return Err("a recovery phrase is twenty four words".to_string());
    }
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(24 * 11));
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

#[cfg(feature = "client")]
pub use client::Client;

#[cfg(feature = "client")]
mod client {
    use super::*;

    pub struct Client {
        base: String,
        network: Network,
        acknowledge_mainnet: bool,
    }

    fn normalize_base(base: String) -> String {
        base.trim_end_matches('/').to_string()
    }

    impl Client {
        pub fn new(base: impl Into<String>) -> Client {
            let base = base.into();
            let network = Network::for_url(base.clone());
            Client {
                base: normalize_base(base),
                network,
                acknowledge_mainnet: false,
            }
        }

        pub fn for_network(network: Network, acknowledge_mainnet: bool) -> Result<Client, String> {
            let base = network.rpc_url.clone().ok_or_else(|| {
                format!(
                    "the {} network has no rpc endpoint yet, pass the endpoint explicitly with Client::with_network",
                    network.name
                )
            })?;
            if network.is_mainnet && !acknowledge_mainnet {
                return Err("refusing to open a mainnet client without acknowledging it, a mainnet transaction moves real value so the network must be chosen on purpose".to_string());
            }
            Ok(Client {
                base: normalize_base(base),
                network,
                acknowledge_mainnet,
            })
        }

        pub fn with_network(
            base: impl Into<String>,
            network: Network,
            acknowledge_mainnet: bool,
        ) -> Client {
            Client {
                base: normalize_base(base.into()),
                network,
                acknowledge_mainnet,
            }
        }

        pub fn network(&self) -> &Network {
            &self.network
        }

        fn guard_mainnet(&self) -> Result<(), String> {
            if self.network.is_mainnet && !self.acknowledge_mainnet {
                let label = self.network.chain_id.clone().unwrap_or_default();
                return Err(format!(
                    "refusing to sign for the mainnet network {label} without acknowledging it, acknowledge mainnet when you mean to move real value"
                ));
            }
            Ok(())
        }

        fn signing_chain_id(&self, info: &NodeInfo) -> Result<u64, String> {
            let name = &info.chain_id;
            if name.is_empty() {
                return Err(
                    "the gateway did not report a chain id to bind the signature to".to_string(),
                );
            }
            if let Some(configured) = &self.network.chain_id {
                if name != configured {
                    return Err(format!(
                        "the gateway reports chain {name} but this client is configured for {configured}, refusing to sign a transaction that would be valid on a network you did not choose"
                    ));
                }
            }
            Ok(chain_id_from_name(name))
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

        pub fn transfer(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            to: &str,
            amount: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(to) {
                return Err("the recipient is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let chain_id = self.signing_chain_id(&info)?;
            let signed =
                sign_transfer(seed, index, to, amount, account.nonce, info.transfer_fee, chain_id)?;
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }

        pub fn call(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            self.call_payable(seed, index, target, args, 0, meter_limit, max_fee)
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_payable(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            target: &str,
            args: Vec<u8>,
            value: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            if !valid_address(target) {
                return Err("the target is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let chain_id = self.signing_chain_id(&info)?;
            let signed = sign_payable_call(
                seed,
                index,
                target,
                args,
                value,
                account.nonce,
                meter_limit,
                info.transfer_fee,
                chain_id,
            )?;
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome))
        }

        pub fn storage(&self, contract: &str) -> Result<Vec<contract::StorageSlot>, String> {
            contract::parse_storage(&self.rpc("get_storage", contract::storage_body(contract))?)
        }

        pub fn events(&self, height: u64) -> Result<Vec<contract::ContractEvent>, String> {
            contract::parse_events(&self.rpc("get_events", contract::events_body(height))?)
        }

        pub fn contract_nonce(&self, contract: &str, signer: &[u8; 32]) -> Result<u64, String> {
            let key = crate::contract::nonce_slot_key(signer);
            Ok(crate::contract::storage_value(&self.storage(contract)?, &key))
        }

        pub fn contract_scalar(&self, contract: &str, slot: u64) -> Result<u64, String> {
            let key = crate::contract::scalar_slot_key(slot);
            Ok(crate::contract::storage_value(&self.storage(contract)?, &key))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_signed_order(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            layout: &contract::OrderLayout,
            fields: &[u64],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            if !valid_address(contract) {
                return Err("the contract is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let chain_id = self.signing_chain_id(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let nonce = self.contract_nonce(contract, &signer)?;
            let order = contract::build_signed_order_call(
                chain_id,
                contract,
                selector,
                layout,
                fields,
                owner_seed,
                owner_index,
                nonce,
            )?;
            let caller = account_address(caller_seed, caller_index);
            let account = self.account(&caller)?;
            let signed = sign_call(
                caller_seed,
                caller_index,
                contract,
                order.call_args.clone(),
                account.nonce,
                meter_limit,
                info.transfer_fee,
                chain_id,
            )?;
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome, order))
        }

        #[allow(clippy::too_many_arguments)]
        pub fn call_typed_order(
            &self,
            caller_seed: &[u8; SEED_LEN],
            caller_index: u64,
            contract: &str,
            selector: [u8; 4],
            scheme_off: u64,
            ptr_off: u64,
            region_off: u64,
            fields: &[contract::FieldArg],
            owner_seed: &[u8; SEED_LEN],
            owner_index: u64,
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, contract::SignedOrderCall), String> {
            if !valid_address(contract) {
                return Err("the contract is not a Q1 address".to_string());
            }
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let chain_id = self.signing_chain_id(&info)?;
            let signer = contract::order_signer(owner_seed, owner_index);
            let nonce = self.contract_nonce(contract, &signer)?;
            let order = contract::build_typed_order_call(
                chain_id, contract, selector, scheme_off, ptr_off, region_off, fields, owner_seed,
                owner_index, nonce,
            )?;
            let caller = account_address(caller_seed, caller_index);
            let account = self.account(&caller)?;
            let signed = sign_call(
                caller_seed,
                caller_index,
                contract,
                order.call_args.clone(),
                account.nonce,
                meter_limit,
                info.transfer_fee,
                chain_id,
            )?;
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome, order))
        }

        pub fn deploy_with_params(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            container: &[u8],
            params: &[contract::DeployParam],
            meter_limit: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit, String), String> {
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let deployer = account_address(seed, index);
            let account = self.account(&deployer)?;
            let args = contract::build_deploy_call(container, params);
            let contract = contract_address(&deployer, account.nonce)
                .ok_or("the deployer is not a Q1 address")?;
            let chain_id = self.signing_chain_id(&info)?;
            let signed = sign_call(
                seed,
                index,
                &vm_deploy_address(),
                args,
                account.nonce,
                meter_limit,
                info.transfer_fee,
                chain_id,
            )?;
            let outcome = self.submit(&signed.tx_bytes)?;
            Ok((signed, outcome, contract))
        }

        pub fn contract_map(
            &self,
            contract: &str,
            map_domain_tag: u64,
            key: &[u8; 32],
        ) -> Result<u64, String> {
            let slot = crate::contract::map_slot_key(map_domain_tag, key);
            Ok(crate::contract::storage_value(&self.storage(contract)?, &slot))
        }

        pub fn register(
            &self,
            seed: &[u8; SEED_LEN],
            index: u64,
            max_fee: u128,
        ) -> Result<(SignedTransfer, Submit), String> {
            let info = self.node_info()?;
            self.guard_mainnet()?;
            if info.transfer_fee > max_fee {
                return Err(format!(
                    "the gateway fee {} is above the maximum you allowed {max_fee}, refusing to sign",
                    info.transfer_fee
                ));
            }
            let sender = account_address(seed, index);
            let account = self.account(&sender)?;
            let chain_id = self.signing_chain_id(&info)?;
            let signed = sign_register(seed, index, account.nonce, info.transfer_fee, chain_id)?;
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
        let transfer = sign_transfer(&seed, 0, &to, 1000, 3, 500, LOCAL_CHAIN_ID).unwrap();
        let mut encoder = Encoder::new();
        encoder.put_u64(1000);
        let call = sign_call(
            &seed,
            0,
            &to,
            encoder.into_bytes(),
            3,
            NATIVE_TRANSFER_METER,
            500,
            LOCAL_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(transfer.tx_bytes, call.tx_bytes);
        assert_eq!(transfer.tx_id, call.tx_id);
    }

    #[test]
    fn a_derived_address_renders_uppercase_q1() {
        let address = account_address(&[7u8; SEED_LEN], 0);
        assert!(address.starts_with("Q1"));
        assert_eq!(address, address.to_ascii_uppercase());
    }

    #[test]
    fn a_payable_call_binds_the_value_into_the_signature() {
        let seed = [7u8; SEED_LEN];
        let target = account_address(&seed, 1);
        let free = sign_call(&seed, 0, &target, vec![1, 2, 3], 5, 1210, 500, LOCAL_CHAIN_ID).unwrap();
        let payable_zero =
            sign_payable_call(&seed, 0, &target, vec![1, 2, 3], 0, 5, 1210, 500, LOCAL_CHAIN_ID)
                .unwrap();
        assert_eq!(free.tx_bytes, payable_zero.tx_bytes);
        assert_eq!(free.tx_id, payable_zero.tx_id);
        let funded =
            sign_payable_call(&seed, 0, &target, vec![1, 2, 3], 1000, 5, 1210, 500, LOCAL_CHAIN_ID)
                .unwrap();
        assert_ne!(funded.tx_bytes, free.tx_bytes);
        assert_ne!(funded.tx_id, free.tx_id);
    }

    #[test]
    fn the_signed_bytes_match_the_chain_body_and_verify() {
        let seed = [7u8; SEED_LEN];
        let sender = derive(&seed, 0);
        let target = account_address(&seed, 1);
        let call = Call::new(target.clone(), vec![9, 9, 9]);
        let body = Body::with_context(sender.address(), 4, 1210, 750, call, 2500, LOCAL_CHAIN_ID);
        let wrapper = sign(&sender, &body);
        assert!(qtv_tx::verify(&wrapper, sender.public_key()));
        let signed =
            sign_payable_call(&seed, 0, &target, vec![9, 9, 9], 2500, 4, 1210, 750, LOCAL_CHAIN_ID)
                .unwrap();
        assert_eq!(signed.tx_bytes, to_bytes(&wrapper));
        assert_eq!(signed.tx_id, wrapper.id());
    }

    #[test]
    fn address_case_cannot_change_the_signature() {
        let seed = [7u8; SEED_LEN];
        let target = account_address(&seed, 1);
        let lowered = target.to_ascii_lowercase();
        assert_ne!(target, lowered);
        let upper = sign_call(&seed, 0, &target, vec![4, 2], 9, 1210, 500, LOCAL_CHAIN_ID).unwrap();
        let lower = sign_call(&seed, 0, &lowered, vec![4, 2], 9, 1210, 500, LOCAL_CHAIN_ID).unwrap();
        assert_eq!(upper.tx_bytes, lower.tx_bytes);
        assert_eq!(upper.tx_id, lower.tx_id);
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
    fn valid_address_rejects_a_payload_wider_than_the_canonical_address() {
        let canonical = account_address(&[7u8; SEED_LEN], 0);
        assert_eq!(qtv_idfmt::parse_address(&canonical).unwrap().len(), ADDRESS_PAYLOAD_LEN);
        let over_wide = qtv_idfmt::render_address(&[0x11u8; ADDRESS_PAYLOAD_LEN + 1]).unwrap();
        assert!(qtv_idfmt::parse_address(&over_wide).is_ok(), "the wide form is still a well formed bech32m string");
        assert!(!valid_address(&over_wide), "a payload wider than the canonical address is not a Q1 address");
        let far_wider = qtv_idfmt::render_address(&[0x11u8; ADDRESS_PAYLOAD_LEN + 8]).unwrap();
        assert!(!valid_address(&far_wider));
        assert!(
            sign_transfer(&[7u8; SEED_LEN], 0, &over_wide, 1000, 0, 500, LOCAL_CHAIN_ID).is_err(),
            "a transfer to an over wide target is refused before signing"
        );
        assert!(
            sign_call(&[7u8; SEED_LEN], 0, &over_wide, vec![1, 2], 0, 1210, 500, LOCAL_CHAIN_ID).is_err()
        );
    }

    #[test]
    fn a_bad_target_is_an_error_not_a_panic() {
        let seed = [7u8; SEED_LEN];
        assert!(sign_transfer(&seed, 0, "not an address", 1000, 0, 500, LOCAL_CHAIN_ID).is_err());
        assert!(sign_call(&seed, 0, "", vec![1, 2], 0, 1210, 500, LOCAL_CHAIN_ID).is_err());
        assert!(
            sign_payable_call(&seed, 0, "Q1zzz", vec![1], 5, 0, 1210, 500, LOCAL_CHAIN_ID).is_err()
        );
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
        assert_eq!(
            account_address(&seed_from_mnemonic(&phrase).unwrap(), 0),
            account_address(&seed, 0)
        );
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words[0] = if words[0] == "abandon" { "ability" } else { "abandon" };
        assert!(seed_from_mnemonic(&words.join(" ")).is_err());
    }
}
