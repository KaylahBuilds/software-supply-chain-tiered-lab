# Security and publication boundaries

The core lab is offline and uses synthetic components. Do not replace them with customer data, internal source, credentials, or private packages and then publish the outputs. Keep the build and mutation exercises disposable.

Never commit tokens, passwords, private keys, or real environment files. Ignore patterns are not a complete secret scanner. Review the exact files and their contents before publishing. Use approved credential storage and short-lived, scoped identities when adapting the examples to a real environment.

The default workflow needs no repository secrets, signing authority, registry writes, or cloud credentials. Do not give untrusted pull-request code privileged tokens or trusted release-runner access. Do not change a `pull_request` workflow into a privileged `pull_request_target` checkout of the submitted branch.

The optional signing template is inactive. Enabling it grants a workflow OIDC and attestation-write authority and can publish build-identity metadata for public artifacts. Review that scope and the audience before activation. Do not include internal paths, private repository details, or sensitive build inputs in public attestations. No private signing key needs to be committed.

The local build record is unsigned, and local consistency is not authenticity. Do not use a `verified: true` field from an input file, a checksum from the same untrusted download, or this lab's local verifier as deployment authorization. Use a maintained cryptographic verifier and an independent trust policy.

For unintended security issues, use the maintainer's contact link on [kaylahbuilds.io](https://kaylahbuilds.io/) with a sanitized summary. Agree on a private channel before sharing sensitive evidence. Do not upload raw tokens, private artifacts, or credentials to public issues.
