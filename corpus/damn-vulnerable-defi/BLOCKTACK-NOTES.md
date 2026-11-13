# BlockTack vendoring notes

Upstream: https://github.com/tinchoabbate/damn-vulnerable-defi (MIT),
cloned at the latest `main`, then:

- Trimmed to three challenges — `side-entrance`, `naive-receiver`,
  `puppet-v2` — plus the shared `DamnValuableToken` and the libs and
  Uniswap build artifacts those challenges need. All other challenges,
  libraries, CI/devcontainer config and submodule metadata were removed.
- Filled in the challenge solutions in the upstream test files
  (`CODE YOUR SOLUTION HERE` slots) and renamed the solution tests to
  `test_poc_*` so BlockTack's foundry adapter recognizes them as
  confirmed PoC findings.
- The upstream license and README are preserved.

Upstream challenge code is untouched: all modifications live in the
test files, exactly where the upstream invites players to write
solutions.

Weakness mapping (see corpus/manifest.yaml):
- side-entrance  -> BTV-L2-001 (balance accounting / reentrancy-adjacent)
- naive-receiver -> BTV-L2-002 (broken access control: sender forgery)
- puppet-v2      -> BTV-L2-003 (manipulable price oracle)
