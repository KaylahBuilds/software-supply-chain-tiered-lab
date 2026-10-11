# Tier 1 — know and review the inputs

Start at the source boundary: dependency identity, resolved version, source, content, owner, and update process. Review package names and publishers to reduce typosquatting/dependency-confusion risk; configure approved registries and namespace boundaries explicitly. A checksum cannot decide whether you intended to trust the publisher.

## Exercise: lock the bytes, then reject drift

Read `fixtures/components.lock.json` alongside the synthetic component files. The lock describes exactly which inputs the teaching builder accepts. Then run:

```sh
python -m lab.build --output artifacts-tier1
python -m lab.verify --output artifacts-tier1
python -m unittest discover -s tests -v
```

Inspect the mutation tests before editing anything. In a disposable copy, change a fixture file without updating its reviewed digest and build to a new output directory. The build must reject the mismatch. Do not repair the exercise by silently accepting whichever bytes arrived.

Review a dependency update as a change to both intent and content: source identity, version, digest, behavior, license obligations, vulnerability information, and tests. Updating a lock is an approval decision, not automatic evidence of trust. Preserve the original repo when experimenting; the tests use temporary directories.

This lab's custom JSON lock is **not a package-manager implementation**. For a real ecosystem, commit the appropriate manifest/lock files and use locked installs such as `npm ci` or a reviewed equivalent. Pins and integrity checks narrow unexpected changes but do not make an approved malicious version safe. Install scripts and build hooks are executable supply-chain inputs too.

## Exercise: inspect the SBOM's scope

Open `artifacts-tier1/bom.cdx.json` and identify its component names, versions, and hashes. Compare them with the packaged fixture bytes. This small CycloneDX 1.6 inventory deliberately covers the synthetic fixtures—not the operating system, runner tools, a container base, or an entire real dependency graph.

In production, generate the inventory from the actual artifact or resolved build inputs using a supported ecosystem tool. Associate it with the released digest and retain it where responders can find it. Validate the document against the intended format/version and disclose omissions. See [CycloneDX capabilities](https://cyclonedx.org/capabilities/).

## What to verify before progressing

- A reviewed lock exists, builds use it, and unexpected dependency changes fail.
- Dependency updates have an owner, review process, tests, and remediation expectations.
- The SBOM describes the relevant artifact and declares its scope.
- A dependency vulnerability report is interpreted separately from the inventory.
- Secret exposure, suspicious package identity, and malicious behavior are not reduced to a CVE count.

## What this tier does not establish

It does not authenticate the build service, prevent a maintainer from approving bad code, attest a release, or ensure the same bytes were deployed. An attacker able to modify both the component and its trusted lock can replace both. Protect the source review boundary and continue with [Tier 2](../tier-2-controlled-builds/README.md).
