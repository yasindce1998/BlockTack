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

## The first replay: naive-oracle-vault

`corpus/fixtures/naive-oracle-vault/` is a synthetic fixture for
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
BTV-L2-003), `Exploit profit verified` (critical), and
`PoC passed: test_poc_oracle_manipulation_drains_vault` (critical,
confirmed).
