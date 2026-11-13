# The known-exploits regression corpus

Every tool claims to find bugs; BlockTack proves it by replaying history.

`manifest.yaml` lists real incidents (bridges compromised, oracles
manipulated, vaults drained) with their taxonomy weakness and a status:

| status       | meaning                                                        |
|--------------|----------------------------------------------------------------|
| `pending`    | not yet covered                                                |
| `detected`   | recon/scan/tooling flags the weakness class on a replayed target |
| `reproduced` | a playbook executes the exploit end to end with verified PnL   |

The platform's headline metric is the count of `reproduced` entries.
When you add coverage for an incident:

1. Vendor the vulnerable target (or a faithful reproduction) under
   `corpus/<incident-id>/` with a target YAML.
2. Write or extend a playbook that executes the exploit class.
3. Flip the manifest status and record how detection happened.

## The first replay: naive-oracle-vault`corpus/fixtures/naive-oracle-vault/` is a synthetic fixture for
BTV-L2-003 (manipulable price oracle — the Mango Markets / Euler shape):
a vault that values collateral with a skewable feed. The campaign in
`playbooks/evm/naive-oracle-vault.yaml` boots anvil, deploys the fixture,
maps its oracle dependency from deployed bytecode, executes the attack
on-chain, verifies profit, and cross-checks with a forge PoC test.

Requires [Foundry](https://getfoundry.sh). Run from the repo root:

```sh
bin/blocktack campaign \
  --target corpus/fixtures/naive-oracle-vault/target.yaml \
  --playbook playbooks/evm/naive-oracle-vault.yaml
```

Expected findings: `Oracle dependency: latestAnswer()` (medium,
BTV-L2-003), `Call succeeds in simulation: borrow(uint256)` (medium —
state-override verification without a broadcast), `Exploit profit
verified` (critical), and `PoC passed:
test_poc_oracle_manipulation_drains_vault` (critical, confirmed).

## Second replay: reentrant-vault

`corpus/fixtures/reentrant-vault/` is a synthetic fixture for
BTV-L2-001 (reentrancy — external call before state update). The
campaign in `playbooks/evm/reentrant-vault.yaml` deploys a vulnerable
vault and attacker contract, first drains the vault **in pure
simulation** (eth_call executes the full reentrancy without
broadcasting anything), then executes the attack on-chain and verifies
profit with a forge PoC cross-check.

```sh
bin/blocktack campaign \
  --target corpus/fixtures/reentrant-vault/target.yaml \
  --playbook playbooks/evm/reentrant-vault.yaml
```

## Wargame corpus: Damn Vulnerable DeFi

`corpus/damn-vulnerable-defi/` vendors (trimmed) three challenges from
[Damn Vulnerable DeFi](https://damnvulnerabledefi.xyz) with solutions
written as `test_poc_*` tests — the first entries with **real-world
challenge provenance**, tracked in `manifest.yaml` under `wargames`:

| Challenge    | Weakness    | Exploit                                            |
|--------------|-------------|----------------------------------------------------|
| side-entrance  | BTV-L2-001 | flash loan "repaid" via the pool's own deposit    |
| naive-receiver | BTV-L2-002 | fee drain + `_msgSender()` forgery via delegatecall |
| puppet-v2      | BTV-L2-003 | oracle crash by dumping tokens into the price pair |
| compromised    | BTV-L2-003 | two of three oracle source keys leaked; median crashed to buy an NFT for 1 wei, then pumped to drain the exchange |
| the-rewarder   | BTV-L2-009 | distributor's double-claim bitmap latches once per run; one valid Merkle claim replays ~1700x in a single call |
| free-rider     | BTV-L5-003 | buyMany pays once for all NFTs and refunds the buyer; V2 flash swap funds the stake — ~120 ETH extracted |

```sh
bin/blocktack campaign \
  --target corpus/damn-vulnerable-defi/target.yaml \
  --playbook playbooks/evm/damn-vulnerable-defi.yaml
```

Three confirmed critical PoC findings and two composed kill chains —
six PoCs total across the full wargame corpus.
