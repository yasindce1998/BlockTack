//! Uniswap v4 hook attack-surface audit: decode a hook's permission
//! bitmap from its address and probe every enabled callback for
//! missing PoolManager access control.
//!
//! v4 calls a hook's callbacks from the PoolManager singleton; the
//! canonical hardening is an `onlyPoolManager` guard (the upstream
//! `BaseHook` gained one after Cork). A callback that parses parameters
//! or hookData before verifying its caller — or executes outright for a
//! foreign caller — is the Cork Protocol exploit class (2025-05-28,
//! ~$12M): the attacker called `beforeSwap` directly with crafted
//! hookData and spoofed deposits. This action probes each enabled
//! callback with read-only `eth_call`s from a neutral address and from
//! the PoolManager itself, then classifies the differential.
//!
//! Read-only: eth_call never mutates state, so this audit is safe
//! against live targets.

use crate::actions::connect;
use crate::finding::Finding;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;

/// Uniswap v4 PoolManager singleton on Ethereum mainnet.
const POOL_MANAGER_MAINNET: &str = "0x000000000004444c5dc75cb358380d2e3de08a90";

/// Neutral probe sender: not the PoolManager, not zero, not the hook.
const PROBE_SENDER: &str = "0x0000000000000000000000000000000000008008";

/// Hook permission flags, from v4-core `Hooks.sol` (address bits 13..0).
const BEFORE_INITIALIZE: u64 = 1 << 13;
const AFTER_INITIALIZE: u64 = 1 << 12;
const BEFORE_ADD_LIQUIDITY: u64 = 1 << 11;
const AFTER_ADD_LIQUIDITY: u64 = 1 << 10;
const BEFORE_REMOVE_LIQUIDITY: u64 = 1 << 9;
const AFTER_REMOVE_LIQUIDITY: u64 = 1 << 8;
const BEFORE_SWAP: u64 = 1 << 7;
const AFTER_SWAP: u64 = 1 << 6;
const BEFORE_DONATE: u64 = 1 << 5;
const AFTER_DONATE: u64 = 1 << 4;
const BEFORE_SWAP_RETURNS_DELTA: u64 = 1 << 3;
const AFTER_SWAP_RETURNS_DELTA: u64 = 1 << 2;
const AFTER_ADD_LIQUIDITY_RETURNS_DELTA: u64 = 1 << 1;
const AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA: u64 = 1 << 0;

struct Callback {
    name: &'static str,
    flag: u64,
    /// Number of 32-byte static head words before the trailing
    /// `bytes hookData` offset word, counting the leading `address
    /// sender` and the 5-word PoolKey.
    head_words: usize,
}

/// The ten action callbacks IHooks defines (the *returns-delta flags
/// do not add callables). Signatures follow IHooks; every callback ends
/// in `bytes hookData`, the only dynamic parameter.
const CALLBACKS: &[Callback] = &[
    Callback {
        name: "beforeInitialize",
        flag: BEFORE_INITIALIZE,
        head_words: 7,
    }, // sender + key(5) + sqrtPrice
    Callback {
        name: "afterInitialize",
        flag: AFTER_INITIALIZE,
        head_words: 8,
    }, // + tick
    Callback {
        name: "beforeAddLiquidity",
        flag: BEFORE_ADD_LIQUIDITY,
        head_words: 10,
    }, // + ModifyLiquidityParams(4)
    Callback {
        name: "afterAddLiquidity",
        flag: AFTER_ADD_LIQUIDITY,
        head_words: 12,
    }, // + delta + feesAccrued
    Callback {
        name: "beforeRemoveLiquidity",
        flag: BEFORE_REMOVE_LIQUIDITY,
        head_words: 10,
    },
    Callback {
        name: "afterRemoveLiquidity",
        flag: AFTER_REMOVE_LIQUIDITY,
        head_words: 12,
    },
    Callback {
        name: "beforeSwap",
        flag: BEFORE_SWAP,
        head_words: 9,
    }, // + SwapParams(3)
    Callback {
        name: "afterSwap",
        flag: AFTER_SWAP,
        head_words: 10,
    }, // + BalanceDelta
    Callback {
        name: "beforeDonate",
        flag: BEFORE_DONATE,
        head_words: 8,
    }, // + amount0 + amount1
    Callback {
        name: "afterDonate",
        flag: AFTER_DONATE,
        head_words: 8,
    },
];

/// hook-audit: audit a Uniswap v4 hook's callback attack surface.
///
/// options:
///   hook:        the v4 hook contract address (required)
///   poolManager: PoolManager address (default: mainnet singleton)
///   rpc-url is supplied by the job envelope as usual
pub async fn hook_audit(
    rpc_url: &str,
    options: &serde_json::Value,
) -> anyhow::Result<Vec<Finding>> {
    let hook: Address = options
        .get("hook")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("hook-audit requires options.hook"))?
        .parse()?;
    let pool_manager: Address = options
        .get("poolManager")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(POOL_MANAGER_MAINNET)
        .parse()?;
    let prober: Address = options
        .get("prober")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(PROBE_SENDER)
        .parse()?;

    let provider = connect(rpc_url).await?;

    // A hook must have code; flag the common misconfiguration of
    // auditing a plain EOA or an empty address up front.
    let code = provider.get_code_at(hook).await.unwrap_or_default();
    if code.is_empty() {
        return Ok(vec![Finding::new(
            "engine-evm-hook-audit",
            format!("Hook {} has no code", short(hook)),
            "info",
        )
        .with("confidence", "confirmed")
        .with("layer", "L2")
        .with(
            "description",
            "The audited hook address holds no bytecode; there is nothing to probe.",
        )
        .with("evidence", format!("hook={hook}"))]);
    }

    let addr_int = U256::from_be_slice(hook.as_slice());
    let bitmap: u64 = (addr_int & U256::from(0x3fffu64)).to::<u64>();

    let mut permissions: Vec<&str> = Vec::new();
    for (name, flag) in [
        ("beforeInitialize", BEFORE_INITIALIZE),
        ("afterInitialize", AFTER_INITIALIZE),
        ("beforeAddLiquidity", BEFORE_ADD_LIQUIDITY),
        ("afterAddLiquidity", AFTER_ADD_LIQUIDITY),
        ("beforeRemoveLiquidity", BEFORE_REMOVE_LIQUIDITY),
        ("afterRemoveLiquidity", AFTER_REMOVE_LIQUIDITY),
        ("beforeSwap", BEFORE_SWAP),
        ("afterSwap", AFTER_SWAP),
        ("beforeDonate", BEFORE_DONATE),
        ("afterDonate", AFTER_DONATE),
        ("beforeSwapReturnDelta", BEFORE_SWAP_RETURNS_DELTA),
        ("afterSwapReturnDelta", AFTER_SWAP_RETURNS_DELTA),
        (
            "afterAddLiquidityReturnDelta",
            AFTER_ADD_LIQUIDITY_RETURNS_DELTA,
        ),
        (
            "afterRemoveLiquidityReturnDelta",
            AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA,
        ),
    ] {
        if bitmap & flag != 0 {
            permissions.push(name);
        }
    }

    let mut findings = vec![Finding::new(
        "engine-evm-hook-audit",
        format!("Uniswap v4 hook permissions decoded: {}", short(hook)),
        "info",
    )
    .with("confidence", "confirmed")
    .with("layer", "L2")
    .with(
        "description",
        format!(
            "The hook address encodes {} enabled permissions. The PoolManager will \
             invoke each enabled callback during pool operations; every one of them \
             is part of the hook's attack surface.",
            permissions.len()
        ),
    )
    .with(
        "evidence",
        format!(
            "hook={hook} bitmap=0x{bitmap:04x} permissions={}",
            permissions.join(",")
        ),
    )];

    for cb in CALLBACKS {
        if bitmap & cb.flag == 0 {
            continue;
        }
        let calldata = encode_callback_call(cb, prober, hook);

        let probe_tx = call_to(hook, &calldata, prober);
        let pm_tx = call_to(hook, &calldata, pool_manager);
        let probe = provider.call(probe_tx).await;
        let as_pm = provider.call(pm_tx).await;

        let calldata_hex = format!("0x{}", hex(&calldata));
        let (verdict, severity, detail) = match (&probe, &as_pm) {
            (Ok(_), _) => (
                "UNGUARDED",
                "high",
                format!(
                    "The {} callback executes successfully when called by a \
                     non-PoolManager address. Anyone can invoke it directly with \
                     arbitrary parameters — the Cork Protocol exploit class: a \
                     spoofed direct call with crafted hookData can manipulate \
                     protocol state mid-transaction.",
                    cb.name
                ),
            ),
            (Err(pe), Ok(_) | Err(_)) => {
                let pmsg = pe.to_string();
                if looks_like_access_control(&pmsg) {
                    (
                        "PROTECTED",
                        "info",
                        format!(
                            "The {} callback reverts for a non-PoolManager caller \
                             with an access-control error — the expected hardening.",
                            cb.name
                        ),
                    )
                } else {
                    let same = match &as_pm {
                        Err(ae) => ae.to_string() == pmsg,
                        Ok(_) => false,
                    };
                    if same {
                        (
                            "NO-SENDER-CHECK-OBSERVED",
                            "medium",
                            format!(
                                "The {} callback reaches the same failure whether \
                                 called by a foreign address or by the PoolManager \
                                 (identical revert) — no caller validation runs \
                                 before the failing logic. Either the callback lacks \
                                 an onlyPoolManager guard, or its check sits behind \
                                 parameter parsing. Cork-class direct-call spoofing \
                                 may apply; review the guard placement.",
                                cb.name
                            ),
                        )
                    } else {
                        (
                            "SENDER-DEPENDENT",
                            "info",
                            format!(
                                "The {} callback behaves differently for the \
                                 PoolManager and for a foreign caller, so some \
                                 caller-dependent check exists (possibly later in \
                                 the flow than ideal).",
                                cb.name
                            ),
                        )
                    }
                }
            }
        };
        findings.push(
            Finding::new(
                "engine-evm-hook-audit",
                format!("v4 hook callback {}: {}", cb.name, verdict),
                severity,
            )
            .with(
                "confidence",
                if verdict == "UNGUARDED" {
                    "confirmed"
                } else {
                    "probable"
                },
            )
            .with("layer", "L2")
            .with("weakness", "BTV-L2-015")
            .with("description", detail)
            .with(
                "evidence",
                format!(
                    "hook={hook} callback={} probe_sender={prober} pool_manager={pool_manager} \
                     calldata={calldata_hex} probe={probe_res} as_pool_manager={pm_res}",
                    cb.name,
                    probe_res = result_summary(&probe),
                    pm_res = result_summary(&as_pm),
                ),
            ),
        );
    }

    Ok(findings)
}

fn call_to(hook: Address, calldata: &[u8], from: Address) -> TransactionRequest {
    let mut tx = TransactionRequest::default();
    tx.set_to(hook);
    tx.set_from(from);
    tx.set_input(alloy::primitives::Bytes::copy_from_slice(calldata));
    tx
}

fn result_summary<E: std::fmt::Display>(r: &Result<alloy::primitives::Bytes, E>) -> String {
    match r {
        Ok(b) => format!("ok(0x{})", hex(&b[..b.len().min(64)])),
        Err(e) => {
            let s = e.to_string().replace('\n', " ");
            format!("revert({})", s.chars().take(160).collect::<String>())
        }
    }
}

/// Heuristic: does a revert message look like an access-control failure?
fn looks_like_access_control(msg: &str) -> bool {
    let m = msg.to_lowercase();
    let auth_words = [
        "unauthorized",
        "not authorized",
        "access control",
        "forbidden",
        "only",
    ];
    if auth_words.iter().any(|w| m.contains(w)) {
        return true;
    }
    (m.contains("manager") || m.contains("pool")) && (m.contains("sender") || m.contains("caller"))
}

/// ABI-encode a direct call to a hook callback. All parameters are
/// static except the trailing `bytes hookData` (encoded empty). Head
/// layout: sender, PoolKey(5 words), callback params, hookData offset.
fn encode_callback_call(cb: &Callback, sender: Address, hook: Address) -> Vec<u8> {
    let sig = format!(
        "{}(address,(address,address,uint24,int24,address){})",
        cb.name,
        param_tail(cb)
    );
    let sel = alloy::primitives::keccak256(sig.as_bytes())[..4].to_vec();
    let head_words = cb.head_words;
    let mut out = Vec::with_capacity(4 + 32 * (head_words + 2));
    out.extend_from_slice(&sel);
    let mut word = [0u8; 32];

    // address sender (the PoolManager passes msg.sender; we spoof it).
    word[12..].copy_from_slice(sender.as_slice());
    out.extend_from_slice(&word);

    // PoolKey: currency0 = ETH(0x0), currency1 = hook (dummy), fee = 3000,
    // tickSpacing = 60, hooks = the audited hook.
    out.extend_from_slice(&[0u8; 32]); // currency0
    word = [0u8; 32];
    word[12..].copy_from_slice(hook.as_slice());
    out.extend_from_slice(&word); // currency1
    out.extend_from_slice(&U256::from(3000u64).to_be_bytes::<32>()); // fee
    out.extend_from_slice(&U256::from(60u64).to_be_bytes::<32>()); // tickSpacing
    word = [0u8; 32];
    word[12..].copy_from_slice(hook.as_slice());
    out.extend_from_slice(&word); // hooks

    // Remaining static parameter words (zeros: the probe cares about the
    // caller check, which canonically runs first).
    for _ in 6..head_words {
        out.extend_from_slice(&[0u8; 32]);
    }

    // Trailing `bytes hookData`: offset word then empty tail.
    out.extend_from_slice(&U256::from((head_words as u64 + 1) * 32).to_be_bytes::<32>()); // offset
    out.extend_from_slice(&[0u8; 32]); // length 0
    out
}

/// The static-parameter tail of each callback signature (after the
/// shared `address,(address,address,uint24,int24,address)` prefix).
fn param_tail(cb: &Callback) -> &'static str {
    match cb.name {
        "beforeInitialize" => ",uint160",
        "afterInitialize" => ",uint160,int24",
        "beforeAddLiquidity" | "beforeRemoveLiquidity" => ",(int256,int24,int24,bytes32),bytes",
        "afterAddLiquidity" | "afterRemoveLiquidity" => {
            ",(int256,int24,int24,bytes32),int256,int256,bytes"
        }
        "beforeSwap" => ",(bool,int256,uint160),bytes",
        "afterSwap" => ",(bool,int256,uint160),int256,bytes",
        "beforeDonate" | "afterDonate" => ",uint256,uint256,bytes",
        _ => unreachable!(),
    }
}

fn short(a: Address) -> String {
    format!("{a}")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_before_swap_probe_calldata() {
        // beforeSwap(address,(address,address,uint24,int24,address),
        // (bool,int256,uint160),bytes): sender + PoolKey(5) +
        // SwapParams(3) = 9 head words + offset + empty hookData tail.
        let hook: Address = "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09"
            .parse()
            .unwrap();
        let sender: Address = "0x0000000000000000000000000000000000008008"
            .parse()
            .unwrap();
        let cb = CALLBACKS.iter().find(|c| c.name == "beforeSwap").unwrap();
        let cd = encode_callback_call(cb, sender, hook);
        // 4-byte selector (keccak of the canonical signature) + 11 words.
        assert_eq!(cd.len(), 4 + 32 * 11);
        assert_eq!(&cd[..4], &[0x57, 0x5e, 0x24, 0xb4]);
        // word 0: sender
        assert_eq!(&cd[4 + 12..4 + 32], sender.as_slice());
        // word 5 (hooks field of PoolKey): the audited hook
        assert_eq!(&cd[4 + 5 * 32 + 12..4 + 6 * 32], hook.as_slice());
        // word 9 (offset to hookData): 10 * 32
        let offset = U256::from_be_slice(&cd[4 + 9 * 32..4 + 10 * 32]);
        assert_eq!(offset, U256::from(320u64));
        // word 10 (hookData length): 0
        let len = U256::from_be_slice(&cd[4 + 10 * 32..4 + 11 * 32]);
        assert_eq!(len, U256::ZERO);
    }

    #[test]
    fn decodes_attacker_hook_bitmap() {
        // The Cork attacker's hook: address low bits 0x3b09 enable
        // before/afterInitialize, beforeAdd/RemoveLiquidity,
        // afterRemoveLiquidity, beforeSwapReturnDelta and
        // afterRemoveLiquidityReturnDelta — but NOT beforeSwap (the
        // spoofing targeted Cork's hook, not the attacker's own).
        let hook: Address = "0x9af3dce0813fd7428c47f57a39da2f6dd7c9bb09"
            .parse()
            .unwrap();
        let bitmap = (U256::from_be_slice(hook.as_slice()) & U256::from(0x3fffu64)).to::<u64>();
        assert_eq!(bitmap, 0x3b09);
        assert_eq!(bitmap & BEFORE_SWAP, 0);
        assert_ne!(bitmap & BEFORE_INITIALIZE, 0);
        assert_ne!(bitmap & BEFORE_SWAP_RETURNS_DELTA, 0);
    }
}
