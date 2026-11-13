# Authorization and rules of engagement

BlockTack is offensive security tooling. Its guardrails are part of the
design, not an afterthought.

## Enforced in code

1. **Every target must declare authorization.** The `authorization` block
   names who authorized the assessment, its scope, and an expiry. The
   runner refuses to start without it.
2. **Safe mode is the default.** Endpoints must be loopback addresses or
   explicitly listed in `authorization.liveTargets`. Safe mode is only
   disabled by passing `--unsafe` explicitly.
3. **The default workflow is local.** Forked chains (anvil `--fork-url`)
   and local testnets reproduce real state without touching live systems.
4. **Campaigns are logged.** Every campaign writes a full step log and
   per-step artifacts to `runs/campaigns/`.

## Expected of the operator

- Only assess systems you are authorized to assess, within the declared
  scope and expiry.
- Never broadcast transactions to a live network from a campaign unless
  that is explicitly authorized *and* you have accepted the consequences.
- Treat exploit PoCs as sensitive artifacts of the engagement.

## Why this matters for the tool itself

A blockchain adversary-simulation platform that cannot demonstrate
authorization discipline is unusable for professional engagements and a
liability for its operator. The guardrails are a feature.
