# VAX Evidence Scan Action

Publishes bounded source evidence from GitHub Actions to VAX. The action runs
local repository scans in CI, uploads evidence to Firebase, and receives a VAX
run URL while the long LLM assessment continues through Pub/Sub.

## Usage

```yaml
name: VAX vendor assurance

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  id-token: write

jobs:
  vax:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run VAX evidence scan
        uses: ata-systems/vax-action@v1
        with:
          vax_key: ${{ secrets.VAX_KEY }}
          scan_levels: asvs-l1,asvs-l2
```

`id-token: write` is required. VAX uses the per-job key to authorize upload to
the configured assessment and the GitHub OIDC token to capture where the job ran.

The action only fails for missing runtime requirements such as `VAX_KEY`, OIDC
permission, or upload failure. Security assessment failures are reported on the
VAX run page instead of failing CI.
