# Tier 2 — control the build and release boundary

The question changes from "are the inputs recorded?" to "who can influence the process that turns them into a release?" Protect workflow definitions, build scripts, dependencies, caches, runner images, and artifact handoffs as part of the build surface.

## Exercise: reproduce an archive

Run two fresh builds from the same fixture input:

```sh
python -m lab.build --output artifacts-a
python -m lab.build --output artifacts-b
python -m lab.verify --output artifacts-a
python -m lab.verify --output artifacts-b
```

Compare the SHA-256 values of the two `source.zip` files with `sha256sum` on Linux or `Get-FileHash -Algorithm SHA256` in PowerShell. The tests also assert deterministic output. The ZIP has fixed ordering, timestamps, and file metadata; no registry resolution or remote build step occurs.

This proves repeatability for the controlled fixture inputs under the tested runtime, not cross-platform reproducibility of arbitrary software, hermetic execution, or resistance to a compromised compiler. A bad input can reproduce perfectly.

## Exercise: test artifact substitution

Review the tests that change the artifact, remove metadata, or mutate its record. Confirm local consistency fails for those individual changes. Then explain the deliberately separate threat: an attacker who can replace the artifact **and recompute its unsigned metadata** can make them agree. This is why the local `lab.verify` command is not a signature verifier or deployment gate.

## Read the active CI boundary

`.github/workflows/checks.yml` uses:

- `contents: read` only, without secrets, OIDC, publishing, or deployment authority.
- Full-commit action pins with `persist-credentials: false` at checkout.
- A hosted runner and bounded job duration; no cache or reusable privileged workspace.
- Tests before fixture packaging, with errors propagated rather than ignored.
- No release/signing step on pull-request events.

The Python runtime and hosted runner remain external dependencies; the workflow is not a fully hermetic build. Full-SHA pins need reviewed updates and do not prove an action is benign. Organization runner policy, required reviews, and branch protection must be configured and verified separately. See [GitHub's secure workflow guidance](https://docs.github.com/en/actions/reference/security/secure-use).

## Production handoff checklist

1. Run untrusted PR checks without secrets, registry-write authority, shared privileged caches, or access to release hosts.
2. Protect workflow/build-policy changes with independent review; ensure required checks actually block an intentionally failing sandbox PR.
3. Build the approved revision, identify the resulting digest, and promote those exact bytes rather than rebuilding after approval.
4. Bind cache keys to relevant inputs and enforce trust separation; never consume attacker-writable caches or artifacts in privileged release jobs.
5. Prefer ephemeral, isolated runners; restrict outbound access and token scope according to workload requirements.
6. Retain sanitized build evidence with appropriate access and retention. Treat artifacts from PR jobs as untrusted until the release policy validates them.

## Optional signing workflow

The next example is `examples/release-provenance.yml.example`, outside the workflow directory and therefore inactive. It shows a direct, main-only, manually authorized build with separate provenance generation. Before opting in, read [Tier 3](../tier-3-verification/README.md), confirm the audience for published attestations, review the additional job permissions, and protect the source/workflow path. Do not add signing authority to this read-only PR workflow.
