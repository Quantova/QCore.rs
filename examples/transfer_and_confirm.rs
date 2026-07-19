//! Prove the core against a running gateway. Read node info, read the sender's account,

use std::thread::sleep;
use std::time::Duration;

use qcore::{account_address, Client, Submit, TxStatus};

const SEED: [u8; 32] = [11u8; 32];

fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:8645".to_string());
    let client = Client::new(url);

    let info = client.node_info().expect("node info");
    println!(
        "network {} at height {}, transfer fee {} {}",
        info.chain_id, info.head_height, info.transfer_fee, info.denomination
    );

    let sender = account_address(&SEED, 0);
    let recipient = account_address(&SEED, 1);

    let before = client.account(&sender).expect("account");
    println!("sender {} nonce {} balance {}", sender, before.nonce, before.balance);

    let (signed, outcome) = client
        .transfer(&SEED, 0, &recipient, 1000)
        .expect("transfer");
    match outcome {
        Submit::Accepted { state, tx_id } => println!("submitted {tx_id} accepted {state}"),
        Submit::Rejected { reason, .. } => {
            println!("submission rejected: {reason}");
            return;
        }
    }

    for _ in 0..40 {
        match client.transaction(&signed.tx_id).expect("status") {
            TxStatus::Finalised { height, block } => {
                println!("finalised at height {height} in block {block}");
                break;
            }
            TxStatus::Pending => sleep(Duration::from_millis(250)),
            TxStatus::Unknown => {
                println!("the transaction is unknown, it did not land");
                break;
            }
        }
    }

    let after = client.account(&sender).expect("account");
    println!("sender now nonce {} balance {}", after.nonce, after.balance);
    let recip = client.account(&recipient).expect("account");
    println!("recipient balance {}", recip.balance);
    println!(
        "spent {} for a transfer of 1000, the amount plus the fixed fee",
        before.balance - after.balance
    );
}
