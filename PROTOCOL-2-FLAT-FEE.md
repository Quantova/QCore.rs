# Protocol 2 — one flat, USD-locked network fee for every transaction

## What changes

Protocol 1 metered contract calls into the fee: a call paid
`transfer_fee × ceil(meter_limit / 1210)`. Against the locked fee that put a token transfer
at ~4,959×, a QNS registration at ~6,612× and a maximum-meter deploy at ~41,323×.

Protocol 2 locks **every** transaction — native transfers, contract calls and deploys — to the
single flat network fee:

| Transaction | Protocol 1 fee | Protocol 2 fee |
|---|---|---|
| Native transfer | 1 × flat | 1 × flat |
| Token transfer (6,000,000 meter) | 4,959 × flat | 1 × flat |
| QNS register (8,000,000 meter) | 6,612 × flat | 1 × flat |
| Maximum deploy (50,000,000 meter) | 41,323 × flat | 1 × flat |

## Signing core (this crate)

- `vm_call_fee(transfer_fee, meter_limit)` returns `transfer_fee`. The meter limit still bounds
  how much work a call may do and is still checked against the chain ceilings; it no longer
  multiplies the fee.
- A call is signed only when its fee **equals** the flat fee. Below it the chain would reject the
  transaction; above it is never needed, so it is refused. Nobody can pay more to jump the queue,
  and a hostile caller cannot inflate the fee.
- `GATEWAY_PROTOCOL` is `2`. A protocol-2 client refuses a protocol-1 gateway and a protocol-1
  client refuses a protocol-2 gateway, so a wallet never signs a flat fee against a node that
  still meters calls.

## Required node rule (must ship with the relaunch)

1. Charge every transaction exactly the flat `transfer_quon`, whatever its meter limit.
2. Reject a transaction whose fee is not the flat `transfer_quon`.
3. Hold `transfer_quon` inside the locked band of **0.05–0.10 US cents** ($0.0005–$0.0010),
   set from the on-chain oracle. It is never raised for congestion, and there is no priority
   fee or tip.
4. `node_info` reports `"protocol": 2`, `fee.transfer_quon`, and `fee.rate_micro_usd_per_qtov`
   (the oracle rate the wallets use to verify the USD cap).
5. Keep enforcing the meter ceilings as work limits (1,210 to 12,500,000; deploys up to
   50,000,000).

## Wallet behaviour

The wallets cap every fee at the lower of 0.10 US cents at the published oracle rate and
`QTOV/700`, so a gateway that lies about the oracle rate can never make a wallet pay more than
it does today. They apply this cap to every transaction once they run a protocol-2 core.

## Rollout

The node and the wallets move together at the relaunch: the node deploys the rule above and
reports protocol 2, and the wallets bump their core to this version in the same release.
Shipping the wallets first would have every contract call rejected; shipping the node first
would make protocol-1 wallets refuse it. Neither half should go live alone.
