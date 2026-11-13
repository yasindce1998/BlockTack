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
