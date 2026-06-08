# VAX Evidence Scan Action

Generate shareable security evidence reports from GitHub Actions.

VAX runs bounded repository evidence collection in CI, uploads the evidence to
VAX, and publishes a hosted report with findings, evidence references, and
suggested fixes. It is built for small SaaS teams, technical founders,
agencies, freelancers, and fractional CTOs that need client-ready security
reporting from GitHub repositories.

## What VAX does

- Runs evidence collection from GitHub Actions on your repository.
- Supports OWASP ASVS Level 1 inspired, OWASP ASVS Level 2 inspired, OWASP WSTG inspired,
  NIST SP 800-161 Rev. 1 Tier 3 inspired, CMMC Level 2 inspired, and DORA inspired evidence scans.
- Publishes hosted VAX report pages with findings, evidence traceability, and
  suggested fixes.
- Gives you a job-scoped `VAX_KEY` and generated workflow YAML from the VAX app.

## What you get

- A copy-paste GitHub Actions workflow for `.github/workflows/vax.yaml`
- A per-job `VAX_KEY` secret used by the action
- A hosted VAX run URL after each scan
- A shareable report page with findings, evidence, and report history
- Public demo proof:
  - App: [`https://vax.ata.systems`](https://vax.ata.systems)
  - Demo repo: [`AtA-Systems/vax-demo-saas-api`](https://github.com/AtA-Systems/vax-demo-saas-api)
  - Demo report: [`Public sample report`](https://vax.ata.systems/runs/x5WfWTrMRmghDNpIeSxi/aE5MDziBtXtiNvEUejDn)

## When to use VAX

Use VAX when you want practical, shareable security evidence from a GitHub repo
without building a manual review packet by hand.

VAX is a good fit when you need to:

- show buyers or clients how security evidence maps back to repository artifacts
- generate repeatable reports from GitHub Actions
- document security, supply-chain, or resilience controls from bounded evidence
- share a sample report before a longer security review process starts

## What VAX is not

VAX is not a formal OWASP certification, penetration test, compliance audit, or
replacement for a mature AppSec program. It produces ASVS-inspired and
framework-inspired evidence reports from bounded repository evidence.

## BYOK model selection and cost

VAX is bring-your-own-key. You choose your model and provide the API key in the
VAX app when you create a job.

- You pay the model provider directly for inference and token usage.
- VAX charges for job management, CI integration, hosted reports, report
  history, and sharing controls.
- Scan cost depends on repository size, evidence bounds, and model choice.
- In our testing, medium-repository scans have typically cost around $2-$5 in
  model usage depending on model and repository size. That is a directional
  example, not a guaranteed price.

## Setup

1. Create a job in the VAX app at [`https://vax.ata.systems`](https://vax.ata.systems).
2. Choose the scan types and model you want to run.
3. Add your provider API key in the job setup flow.
4. Copy the generated workflow into `.github/workflows/vax.yaml`.
5. Add the generated `VAX_KEY` as a GitHub Actions secret named `VAX_KEY`.
6. Push code or run the workflow manually.
7. Open the hosted VAX run URL to review the report.

## Copy-paste workflow example

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
        uses: AtA-Systems/vax-security-scan@v1
        with:
          vax_key: ${{ secrets.VAX_KEY }}
```

`id-token: write` is required. VAX uses the per-job key to authorize upload to
the configured assessment and the GitHub OIDC token to capture where the job
ran. Scan types are selected in the VAX job configuration, not in the workflow
file.

The action fails for missing runtime requirements such as `VAX_KEY`, OIDC
permission, or upload failure. Security assessment gaps are reported on the VAX
run page instead of failing CI.

## Evidence bounds and cost controls

VAX starts from the repository root by default so the assessor can discover
application code, configuration, and tests without requiring hand-selected
source paths. Uploads are still bounded for CI runtime and token cost: by
default the action includes up to 1,000 prioritized source and configuration
files, up to 8,000,000 total evidence bytes, and up to 40,000 bytes per file.
Files are prioritized toward security-relevant paths and names such as auth,
session, login, OAuth, JWT, CSRF, API, server, and tests.

For frontend-heavy repositories, pass explicit `evidence_paths` or raise the
bounds further so client-side code is represented alongside backend services:

```yaml
with:
  vax_key: ${{ secrets.VAX_KEY }}
  evidence_paths: webapp/packages/webui/src,webapp/packages/api
  max_files: 500
  max_bytes: 4000000
  max_file_bytes: 60000
```

## Typed artifacts

Put supplemental VAX evidence in a `.vax` directory at the repository root.
The action ingests `.vax` automatically. Use it for evidence that should not be
inferred from repository contents alone, such as SBOMs, SLSA provenance,
vulnerability scan exports, POA&M records, risk registers, security plans,
incident response plans, business continuity artifacts, and validation notes.
JSON manifests can also provide explicit control mappings, which replace
inferred results for the same control deterministically:

```json
{
  "artifacts": [
    {
      "type": "sbom",
      "path": "dist/sbom.cdx.json",
      "controls": [
        {
          "framework": "NIST SP 800-161",
          "control_id": "NIST-161-SCRM-05",
          "status": "pass",
          "severity": "medium",
          "detail": "CycloneDX SBOM generated by CI for this build."
        }
      ]
    }
  ]
}
```

Known artifact `type` values also map to local control signals even without an
explicit `controls` array, so typed evidence remains traceable in the scorecard.
See the website docs at `https://vax.ata.systems/docs/evidence-manifest` for a
fuller manifest example, including input/output validation evidence.

## Support

Questions or setup issues: [`support@ata.systems`](mailto:support@ata.systems)
