// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::collections::BTreeSet;

use qtv_attest::attestation::attestation_message;
use qtv_attest::params::ATTEST_CONTEXT;
use qtv_attest::{Attestation, Block, Envelope, Parent};
use qtv_block::{header_from_bytes, verify_inclusion, MerkleProof, MerkleStep};
use qtv_codec::Decoder;
use qtv_crypto::ml_dsa::{self, PUBLIC_KEY_BYTES, SIGNATURE_BYTES};
use qtv_sampler::onetime::{MerklePath, Root, NODE_BYTES, PREIMAGE_BYTES};
use qtv_sampler::params::{MAX_ACTIVE_VALIDATORS, MIN_SELF_STAKE};
use qtv_sampler::sortition::{verify_membership, Credential};

const PARENT_GENESIS: u8 = 0;
const PARENT_VALUE: u8 = 1;
const STAGE_ONE: u8 = 1;
const MAX_ATTESTATIONS: u64 = 4096;
const MAX_CREDENTIAL_SIBLINGS: u64 = 64;
const MAX_ROSTER: usize = 4096;
const MAX_COMMITTEE_REVEALS: u64 = 4096;
const MAX_PROOF_STEPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterMember {
    pub id: u64,
    pub stake: u64,
    pub attest_pk: Vec<u8>,
    pub root: Root,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedHeader {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub q_root: [u8; 32],
    pub transaction_root: [u8; 32],
    pub event_root: [u8; 32],
    pub time: u64,
    pub signed_stake: u128,
    pub total_stake: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEvent {
    pub contract: String,
    pub selector: [u8; 4],
    pub data: Vec<u8>,
}

fn active_set(roster: &[RosterMember]) -> Vec<&RosterMember> {
    let mut active: Vec<&RosterMember> = roster
        .iter()
        .filter(|m| m.stake >= MIN_SELF_STAKE)
        .collect();
    if active.len() > MAX_ACTIVE_VALIDATORS {
        active.sort_by(|a, b| b.stake.cmp(&a.stake).then(a.id.cmp(&b.id)));
        active.truncate(MAX_ACTIVE_VALIDATORS);
    }
    active
}

pub fn verify_finality(
    chain_id: u64,
    genesis_hash: &[u8; 32],
    header_bytes: &[u8],
    certificate_bytes: &[u8],
    roster: &[RosterMember],
) -> Result<FinalizedHeader, String> {
    if roster.is_empty() || roster.len() > MAX_ROSTER {
        return Err("the validator roster is empty or too large".to_string());
    }
    let mut ids = BTreeSet::new();
    for member in roster {
        if !ids.insert(member.id) {
            return Err("the validator roster names a validator twice".to_string());
        }
        if member.attest_pk.len() != PUBLIC_KEY_BYTES {
            return Err("a roster key is not an ML-DSA-65 public key".to_string());
        }
    }
    let roster = active_set(roster);
    let total: u128 = roster
        .iter()
        .map(|m| u128::from(m.stake))
        .fold(0u128, u128::saturating_add);
    if total == 0 {
        return Err("the validator roster carries no stake".to_string());
    }
    let header = header_from_bytes(header_bytes)
        .map_err(|_| "the header bytes are malformed".to_string())?;
    let hash = header.hash();
    let (envelope, attestations) = decode_certificate(certificate_bytes)?;
    if envelope.block.val != hash
        || envelope.block.height != header.height()
        || envelope.height != header.height()
    {
        return Err("the certificate does not name this header".to_string());
    }
    let first_view = attestations
        .first()
        .map(|a| a.view)
        .ok_or_else(|| "the certificate carries no attestations".to_string())?;
    let mut signed: u128 = 0;
    let mut seen = BTreeSet::new();
    for attestation in &attestations {
        if attestation.height != envelope.height
            || attestation.slot != envelope.slot
            || attestation.committee != envelope.committee
            || attestation.block != envelope.block
            || attestation.view != first_view
        {
            return Err("an attestation does not match the certificate it sits in".to_string());
        }
        if !seen.insert(attestation.from) {
            return Err("a validator attests twice in one certificate".to_string());
        }
        let member = roster
            .iter()
            .find(|m| m.id == attestation.from)
            .ok_or_else(|| {
                "an attestation comes from a validator outside the roster".to_string()
            })?;
        let pk: &[u8; PUBLIC_KEY_BYTES] = member
            .attest_pk
            .as_slice()
            .try_into()
            .map_err(|_| "a roster key is not an ML-DSA-65 public key".to_string())?;
        if ml_dsa::public_key_is_degenerate(pk) {
            return Err("a roster key is degenerate".to_string());
        }
        let message = attestation_message(
            qtv_attest::ChainBinding::new(chain_id, *genesis_hash),
            attestation.height,
            attestation.slot,
            attestation.view,
            &attestation.committee,
            &attestation.block,
        );
        if !ml_dsa::verify(pk, &message, &attestation.sig, ATTEST_CONTEXT) {
            return Err("an attestation signature does not verify".to_string());
        }
        if member.stake == 0
            || !verify_membership(
                &member.root,
                attestation.from,
                attestation.slot,
                &attestation.membership,
            )
        {
            return Err("an attestation does not prove its committee membership".to_string());
        }
        signed = signed.saturating_add(u128::from(member.stake));
    }
    if signed.saturating_mul(3) < total.saturating_mul(2) {
        return Err("the attesting validators hold less than two thirds of the stake".to_string());
    }
    Ok(FinalizedHeader {
        height: header.height(),
        hash,
        parent_hash: *header.parent_hash(),
        q_root: *header.q_root(),
        transaction_root: *header.transaction_root(),
        event_root: *header.event_root(),
        time: header.time(),
        signed_stake: signed,
        total_stake: total,
    })
}

pub fn verify_event(event_root: &[u8; 32], leaf: &[u8], steps: &[([u8; 32], bool)]) -> bool {
    if steps.len() > MAX_PROOF_STEPS {
        return false;
    }
    let proof = MerkleProof {
        steps: steps
            .iter()
            .map(|(sibling, left)| MerkleStep {
                sibling: *sibling,
                sibling_on_left: *left,
            })
            .collect(),
    };
    verify_inclusion(event_root, leaf, &proof)
}

pub fn verify_transaction(
    transaction_root: &[u8; 32],
    tx_id: &str,
    leaf: &[u8],
    steps: &[([u8; 32], bool)],
) -> bool {
    let hash = qtv_crypto::sha3::sha3_256(leaf);
    match qtv_idfmt::render_tx(&hash) {
        Ok(id) if id == tx_id => verify_event(transaction_root, leaf, steps),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedTransaction {
    pub tx_id: String,
    pub index: u64,
    pub header: FinalizedHeader,
}

pub fn parse_roster(text: &str) -> Result<Vec<RosterMember>, String> {
    let parsed = crate::json::parse(text)?;
    let items = match &parsed {
        crate::json::Json::Array(items) => items,
        _ => return Err("the validator roster must be a JSON array".to_string()),
    };
    if items.len() > MAX_ROSTER {
        return Err("the validator roster is too large".to_string());
    }
    let digits = |item: &crate::json::Json, key: &str| -> Result<u64, String> {
        let text = item
            .get(key)
            .and_then(crate::json::Json::as_str)
            .ok_or_else(|| format!("a roster member needs {key} as a digit string"))?;
        crate::canonical_decimal(text)
            .and_then(|n| u64::try_from(n).ok())
            .ok_or_else(|| format!("a roster {key} is not a canonical whole number in range"))
    };
    let mut roster = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(crate::json::Json::as_u64)
            .ok_or_else(|| "a roster member needs a numeric id".to_string())?;
        let attest_pk = crate::json::from_hex(
            item.get("attest_pk")
                .and_then(crate::json::Json::as_str)
                .ok_or_else(|| "a roster member needs an attest_pk".to_string())?,
        )?;
        let digest: [u8; 32] = crate::json::from_hex(
            item.get("root")
                .and_then(crate::json::Json::as_str)
                .ok_or_else(|| "a roster member needs its sortition root".to_string())?,
        )?
        .try_into()
        .map_err(|_| "a roster root is 32 bytes of hex".to_string())?;
        roster.push(RosterMember {
            id,
            stake: digits(item, "stake")?,
            attest_pk,
            root: Root {
                digest,
                slots: digits(item, "root_slots")?,
            },
        });
    }
    Ok(roster)
}

pub fn parse_steps(steps: &crate::json::Json) -> Result<Vec<([u8; 32], bool)>, String> {
    let items = match steps {
        crate::json::Json::Array(items) => items,
        _ => return Err("the proof steps must be a list".to_string()),
    };
    if items.len() > MAX_PROOF_STEPS {
        return Err("the proof has too many steps".to_string());
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let sibling: [u8; 32] = item
            .get("sibling")
            .and_then(crate::json::Json::as_str)
            .ok_or_else(|| "a proof step needs a sibling".to_string())
            .and_then(crate::json::from_hex)?
            .try_into()
            .map_err(|_| "a proof sibling is 32 bytes".to_string())?;
        let left = match item.get("left") {
            Some(crate::json::Json::Bool(b)) => *b,
            _ => return Err("a proof step needs a boolean left".to_string()),
        };
        out.push((sibling, left));
    }
    Ok(out)
}

pub fn decode_event(leaf: &[u8]) -> Result<ChainEvent, String> {
    let malformed = || "the event leaf is malformed".to_string();
    let mut decoder = Decoder::new(leaf);
    let contract = String::from_utf8(decoder.get_bytes().map_err(|_| malformed())?.to_vec())
        .map_err(|_| malformed())?;
    let selector: [u8; 4] = decoder
        .get_bytes()
        .map_err(|_| malformed())?
        .try_into()
        .map_err(|_| malformed())?;
    let data = decoder.get_bytes().map_err(|_| malformed())?.to_vec();
    decoder.finish().map_err(|_| malformed())?;
    Ok(ChainEvent {
        contract,
        selector,
        data,
    })
}

fn decode_certificate(bytes: &[u8]) -> Result<(Envelope, Vec<Attestation>), String> {
    let mut decoder = Decoder::new(bytes);
    let envelope = decode_envelope(&mut decoder)?;
    if decoder.get_u8().map_err(codec)? != STAGE_ONE {
        return Err("the certificate stage is not supported".to_string());
    }
    let count = decoder.get_u64().map_err(codec)?;
    if count > MAX_ATTESTATIONS {
        return Err("the certificate carries too many attestations".to_string());
    }
    let mut attestations = Vec::new();
    for _ in 0..count {
        attestations.push(decode_attestation(&mut decoder)?);
    }
    let reveals = decoder.get_u64().map_err(codec)?;
    if reveals > MAX_COMMITTEE_REVEALS {
        return Err("the certificate carries too many committee reveals".to_string());
    }
    for _ in 0..reveals {
        decoder.get_u64().map_err(codec)?;
        decode_credential(&mut decoder)?;
    }
    decoder.finish().map_err(codec)?;
    Ok((envelope, attestations))
}

fn decode_envelope(decoder: &mut Decoder<'_>) -> Result<Envelope, String> {
    let height = decoder.get_u64().map_err(codec)?;
    let slot = decoder.get_u64().map_err(codec)?;
    let block = decode_block(decoder)?;
    let committee: [u8; 32] = read_array(decoder)?;
    Ok(Envelope {
        height,
        slot,
        block,
        committee,
    })
}

fn decode_block(decoder: &mut Decoder<'_>) -> Result<Block, String> {
    let height = decoder.get_u64().map_err(codec)?;
    let val = read_value(decoder)?;
    let parent_tag = decoder.get_u8().map_err(codec)?;
    let parent_value = read_value(decoder)?;
    let parent = match parent_tag {
        PARENT_GENESIS => Parent::Genesis,
        PARENT_VALUE => Parent::Value(parent_value),
        _ => return Err("the certificate block parent tag is unknown".to_string()),
    };
    let cost = decoder.get_u64().map_err(codec)?;
    Ok(Block {
        height,
        val,
        parent,
        cost,
    })
}

fn decode_attestation(decoder: &mut Decoder<'_>) -> Result<Attestation, String> {
    let from = decoder.get_u64().map_err(codec)?;
    let height = decoder.get_u64().map_err(codec)?;
    let slot = decoder.get_u64().map_err(codec)?;
    let view = decoder.get_u64().map_err(codec)?;
    let committee: [u8; 32] = read_array(decoder)?;
    let block = decode_block(decoder)?;
    let membership = decode_credential(decoder)?;
    let sig: [u8; SIGNATURE_BYTES] = read_array(decoder)?;
    Ok(Attestation {
        from,
        height,
        slot,
        view,
        committee,
        block,
        membership,
        sig,
    })
}

fn decode_credential(decoder: &mut Decoder<'_>) -> Result<Credential, String> {
    let position = decoder.get_u64().map_err(codec)?;
    let preimage: [u8; PREIMAGE_BYTES] = read_array(decoder)?;
    let count = decoder.get_u64().map_err(codec)?;
    if count > MAX_CREDENTIAL_SIBLINGS {
        return Err("a credential path is too long".to_string());
    }
    let mut siblings = Vec::new();
    for _ in 0..count {
        let sibling: [u8; NODE_BYTES] = read_array(decoder)?;
        siblings.push(sibling);
    }
    Ok(Credential {
        position,
        preimage,
        path: MerklePath { siblings },
    })
}

fn read_array<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], String> {
    decoder
        .get_bytes()
        .map_err(codec)?
        .try_into()
        .map_err(|_| "a fixed certificate field has the wrong length".to_string())
}

fn read_value(decoder: &mut Decoder<'_>) -> Result<[u8; 32], String> {
    let mut value = [0u8; 32];
    for slot in value.iter_mut() {
        *slot = decoder.get_u8().map_err(codec)?;
    }
    Ok(value)
}

fn codec(_: qtv_codec::Error) -> String {
    "the certificate bytes are malformed".to_string()
}
