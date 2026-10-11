# Software supply chain security: three practical tiers

**Know the inputs. Protect the build. Verify what you ship.**

Companion to [the supply chain security field note](https://kaylahbuilds.io/#/blog/software-supply-chain-security-tiers) by Kaylah Builds.

This hands-on repository follows synthetic components through pinned inputs, deterministic packaging, a small SBOM, and artifact verification examples. Its adoption tiers are **not SLSA levels, a certification, or proof that this repository satisfies a security standard**.

## Choose the next trust boundary

| Tier | Main question | Working examples | Remaining boundary |
| --- | --- | --- | --- |
| [1 — Baseline inputs](tier-1-baseline/README.md) | What enters the build, and who approved it? | Local components with reviewed SHA-256 pins; changed-input rejection; a fixture-scoped CycloneDX SBOM. | A pinned malicious input is still malicious; an inventory is not a vulnerability assessment. |
| [2 — Controlled builds](tier-2-controlled-builds/README.md) | Can a change or untrusted job alter the build or gain release authority? | Least-privilege CI; full-SHA action pins; deterministic archive; mutation and consistency tests. | Reproducibility does not establish the builder's identity or isolate a compromised runner. |
| [3 — Verified promotion](tier-3-verification/README.md) | Did an approved builder produce these exact bytes from the reviewed source? | Inactive attestation-generation template; a GitHub CLI verification script with explicit identity and revision policy. | No signed attestation or real deployment is created by the default lab. Verification must gate the actual consumer. |

Higher tiers retain earlier controls. Match rigor to exposure and impact instead of treating every application as the same risk.

## Run the offline examples

Requires Python 3.11+ with its standard library. No third-party Python packages, registries, cloud accounts, containers, credentials, or network calls are needed for the core exercises.

From the repository root:

```sh
python -m unittest discover -s tests -v
python -m lab.build --output artifacts
python -m lab.verify --output artifacts
```

Use `python3` or `py -3` if appropriate for your installation. The output directory must be **new**: reruns should use a fresh name such as `artifacts-second`, not overwrite existing evidence.

| Output | Meaning | What it does not prove |
| --- | --- | --- |
| `source.zip` | Deterministically packaged synthetic input files. | A hermetic production build or trustworthy publisher. |
| `bom.cdx.json` | A small CycloneDX 1.6 inventory of this lab's fixture components. | Complete operating-system/transitive dependency coverage, absence of vulnerabilities, or valid licenses. |
| `build-record.json` | An explicitly unsigned record for local digest/metadata consistency checks. | A signed SLSA attestation, authenticated provenance, or permission to deploy. |

`lab.verify` checks local consistency, **not cryptographic authenticity**. An attacker who can replace the artifact and its unsigned metadata can recompute both. The real attestation verifier lives separately under Tier 3 and delegates signature/trust validation to GitHub CLI.

The fixture lock is a deliberately small teaching format, not an npm, pip, Cargo, or other package-manager lockfile. Production installs should use the ecosystem's own frozen/locked install mechanism and appropriate integrity verification. Exact pins require reviewed updates; freezing forever is not a remediation strategy.

## Repository layout

```text
fixtures/                      Synthetic local components and reviewed lock
lab/                           Offline build and consistency-check commands
tests/                         Positive cases and tampering/mutation regressions
tier-1-baseline/                Input review, lockfiles, SBOM and updates
tier-2-controlled-builds/       CI boundaries and reproducibility exercises
tier-3-verification/            Policy-bound real attestation verification example
examples/release-provenance.yml.example  Inactive, manual-only signing template
.github/workflows/checks.yml    Active read-only offline CI
VALIDATION.md                  Executed checks versus unverified examples
SECURITY.md                    Credential and evidence handling boundaries
```

## What runs automatically?

The active GitHub workflow checks out the submitted revision, runs offline tests, builds a fixture archive, and verifies local consistency. It has read-only repository permissions and does not expose OIDC, sign artifacts, publish packages, deploy, or accept secrets. Pull-request code remains outside release authority.

The separate release example ends in `.yml.example` **outside `.github/workflows`**, so it is inactive. It documents how an authorized maintainer could opt in to public artifact attestations after reviewing permissions, publishing scope, and trust policy. It is manual-only and main-only; do not enable it as a shortcut to claiming SLSA compliance.

GitHub branch protection, required reviews/checks, protected environments, organization policies, registry policy, and admission controls are not enabled by adding this repository. See each tier's verification checklist and [VALIDATION.md](VALIDATION.md).

## Controls are complementary

- Dependency review and vulnerability scans find different problems than signature verification.
- Secret scanning does not revoke a leaked credential. Revoke or rotate first, then remove exposure.
- SBOMs support inventory and incident scoping; they need current vulnerability and ownership context.
- Provenance records origin/build claims; it does not certify that the source is benign.
- Consumers must enforce the approved artifact digest and builder/source policy. Merely creating a signature is not enforcement.

Never commit credentials, private signing keys, tokens, real customer data, or unsanitized reports. Keep generated output local under ignored `artifacts*` directories until its intended publication has been reviewed.

## Further reading

- [SLSA v1.2 specification](https://slsa.dev/spec/v1.2/) and [build-track basics](https://slsa.dev/spec/v1.2/build-track-basics)
- [GitHub secure workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [CycloneDX capabilities](https://cyclonedx.org/capabilities/)
- [OpenSSF Scorecard](https://scorecard.dev/)
- [SAST vs DAST companion lab](https://github.com/KaylahBuilds/sast-dast-tiered-lab)
