# Validation: evidence and limits

Authoring checks performed on 2026-10-10. These results describe this small lab, not a production security certification.

## Executed locally

- **25 offline Python tests passed**, including content-pin drift, malformed/duplicate metadata, path traversal, symlink/reparse-point policy, missing/extra inputs and outputs, archive substitution, metadata tampering, size limits, deterministic bytes, and refusal to overwrite existing output.
- The symlink/reparse tests simulate filesystem metadata so that Windows tests do not require elevated link-creation privileges. They are not an operating-system race-resistance test.
- `python -m lab.build --output artifacts` and `python -m lab.verify --output artifacts` succeeded. The verifier explicitly reported `authenticated=False`.
- A second build to a fresh sibling directory produced identical ZIP, SBOM, and unsigned-record bytes. This demonstrates local determinism, not a hermetic production build or independent builder trust.
- GitHub CLI 2.100.0 help includes the flags required by the Tier 3 policy.
- Full-SHA action references were checked against their upstream repositories. A reviewed pin does not guarantee safe upstream code.

The tests include a deliberately passing consistency check after an attacker rewrites both artifact inputs and unsigned metadata. This documents the missing authenticity boundary; it is not a security bypass hidden by the test suite.

## Automated CI checks

The read-only workflow runs the Python suite, fixture build, and consistency verification. It also checks the optional verifier's POSIX syntax, CLI flag availability, and rejection of missing/invalid arguments, an all-zero commit, and an artifact URL. None of those preflight checks retrieves or authenticates an attestation.

See the [workflow runs](https://github.com/KaylahBuilds/software-supply-chain-tiered-lab/actions/workflows/checks.yml) for executed commit-specific results. Configuration is not itself evidence of a passing run.

## Not verified or activated

- The attestation-generation template remains **inactive**, outside `.github/workflows`. No signing workflow was enabled, no signed attestation generated, and no real signed release verified.
- The local authoring sandbox blocked Git Bash execution. POSIX shell checks are assigned to CI, not claimed as successful local tests.
- The SBOM uses CycloneDX 1.6 structure and a deliberately narrow fixture inventory. Tests check its expected structure and hashes; a full external CycloneDX JSON Schema validator was not run.
- No third-party dependency scanning, secret-scanning product, registry integration, cloud deployment, admission controller, or protected promotion environment was exercised.
- No repository rulesets, branch protection, required reviews, organizational runner controls, or production gates were configured by this lab.
- No SLSA level, compliance status, absence of vulnerabilities, or complete supply-chain inventory is claimed.

Before production adoption, demonstrate signed-artifact acceptance and rejection with independently approved source and builder policy in a controlled environment. Record exact artifact digests, policy, tool versions, expected outcomes, actual results, and any expiring exceptions. Do not substitute unsigned local consistency for authenticated provenance.
