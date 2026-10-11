# Tier 3 — Verify before accepting an artifact

The consumer must decide which source and builder are trusted **before** reading
an artifact's claims. These are this repository's teaching tiers, not official
SLSA levels. The approved [SLSA 1.2 specification](https://slsa.dev/spec/v1.2/)
has its own [build-track requirements](https://slsa.dev/spec/v1.2/build-track-basics).
This lab does not claim that enabling a workflow achieves a particular level.

## Establish a consumer policy

Our example accepts only a reviewed release built from this repository's `main`
ref by the direct `.github/workflows/release-provenance.yml` workflow, using
GitHub-hosted runners. An operator supplies the independently approved source
commit; the source and signer workflow must both match it. A changed build
identity requires a reviewed policy change, not a retry with weaker flags.

The supplied verifier delegates cryptography and artifact-to-attestation digest
comparison to `gh attestation verify`. It does not implement signing, replace
trust roots, inspect an unsigned JSON file as proof, or execute the artifact.
[GitHub CLI verification policy](https://cli.github.com/manual/gh_attestation_verify)

Before accepting a release, review the following **outside the attestation**:

- Which source commit was approved, and who approved it?
- Were changes to the workflow, dependencies, and build instructions reviewed?
- Is the artifact type/name the intended product rather than a similarly named file?
- Were required tests, vulnerability/license decisions, and exceptions satisfied?
- Will the exact verified bytes be promoted without a rebuild or substitution?

Keep the artifact immutable in a consumer-controlled staging location during
verification and promotion. The script is a verifier, not an admission controller
or installer; a separate protected gate must enforce its result. This consumer
policy deliberately uses a fixed main-ref workflow rather than a reusable
builder. Adopting a reusable builder needs a different reviewed signer identity.
[SLSA consumer verification guidance](https://slsa.dev/spec/v1.2/verifying-artifacts)

## Run the verifier on an existing artifact

Use a trusted GitHub CLI installation and POSIX shell. Required flags were
checked against **GitHub CLI 2.100.0** during authoring. `--check` inspects local
help and prints the version; it neither authenticates nor verifies a release.
The verifier fails if the installed CLI lacks a required flag.

From the repository root:

```sh
sh tier-3-verification/verify-release.sh --check
```

After a human has deliberately enabled the optional release example, reviewed
the selected main commit, and obtained that run's `source.zip` using an approved
download process, set the two local inputs and verify:

```sh
ARTIFACT='artifacts/source.zip'
APPROVED_COMMIT='REPLACE_WITH_APPROVED_LOWERCASE_40_HEX_COMMIT'
sh tier-3-verification/verify-release.sh "$ARTIFACT" "$APPROVED_COMMIT"
```

The placeholder must be replaced; the script intentionally rejects it. Do not
automatically discover the commit from the same artifact, unsigned build record,
moving branch, or unverified bundle. The expected commit comes from a trusted
approval record. Online verification fetches signed metadata from GitHub and
uses the CLI's trust configuration; existing authorized read access may be
needed. Do not place tokens in script arguments, files, reports, or Git.

The verifier fixes the repository, workflow, workflow certificate identity,
OIDC issuer, main source ref, exact source/workflow commit, provenance predicate,
runner policy, and SHA-256 subject algorithm. It accepts a regular local file,
not an artifact URL. It does not download the artifact or activate a workflow.
Do not use an owner-only policy, broad identity regex, or fallback to a checksum
if verification fails.

## Relate this to the optional release example

[`examples/release-provenance.yml.example`](../examples/release-provenance.yml.example)
is deliberately outside `.github/workflows/`. A maintainer must separately
review and activate it as `.github/workflows/release-provenance.yml`; this guide
does not authorize activation. It is manual-only and requires the main ref.
The workflow attests only `source.zip`; neither `bom.cdx.json` nor
`build-record.json` is signed by this template. The local unsigned record is only
a debugging/teaching record. It is **not** a signed attestation and cannot pass
as one. A locally built archive does not acquire provenance because it has an
SBOM or matches an unsigned digest file.

GitHub's generation step requires OIDC and attestation-writing permissions.
Those are restricted to the opt-in release job, not the ordinary lab tests.
[GitHub attestation generation](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)

## Demonstrate failure, not only success

In an authorized disposable exercise, verify the original release and then test:

| Mutation or condition | Required decision |
| --- | --- |
| Different artifact bytes | Reject: the attested subject must match the file. |
| Different approved source commit | Reject: source/workflow digests must match policy. |
| No available attestation satisfies the approved repository, workflow, and ref | Reject: identity and source constraints fail. |
| Self-hosted signing runner | Reject under this example's hosted-runner policy. |
| Missing attestation, invalid signature/timestamp, untrusted roots, unavailable service, or CLI failure | Block as failed/incomplete verification; never promote. |
| Valid attestation but unapproved code or failing required tests | Block at the independent release-approval gate. |

Do not edit the verifier's policy to make negative cases pass. Record the exact
artifact digest, approved commit, verifier version, verification result, and
release decision in a restricted evidence system. A nonzero exit status stops
promotion; never hide it with `|| true` or continue-on-error. A signed claim is
not a guarantee that its software is safe or free of malicious behavior.
[GitHub attestation limitations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)

## Offline verification is a separate trust exercise

Offline mode requires the artifact, signed bundle, trusted GitHub CLI, and
independently obtained trusted-root material. GitHub CLI supports `--bundle`
and `--custom-trusted-root`; preserve all the same identity and source-policy
flags. Do not use a root supplied alongside an untrusted artifact as your trust
anchor. Acquire roots through a trusted connected process, authenticate their
transfer, record acquisition time, and refresh when importing new signed
material. Offline roots do not communicate subsequent revocation or rotation.
This online script intentionally has no root-override option.
[GitHub's offline verification guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline),
[trusted-root command](https://cli.github.com/manual/gh_attestation_trusted-root)

Sigstore identity verification also depends on an expected certificate identity
and issuer; accepting any valid signer does not express a useful release policy.
We use GitHub CLI for this GitHub-specific exercise rather than a homemade
signature checker. [Sigstore verification documentation](https://docs.sigstore.dev/cosign/verifying/verify/)

## Authoring validation status

CLI version/help and required flag availability were inspected without login.
The authoring sandbox blocked Git Bash before it could execute; local shell
syntax, script preflight, and negative input checks therefore remain **not run**.
Those local checks are separate from the read-only GitHub CI preflight;
see [VALIDATION.md](../VALIDATION.md) and the linked workflow results. Both are separate from
signature verification. No release workflow was activated, no attestation was
generated, and no real signed artifact was verified. Record a future live result
before claiming the signed release path works; unsigned lab data is not
substitute trust evidence.
