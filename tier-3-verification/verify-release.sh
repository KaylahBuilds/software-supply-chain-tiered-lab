#!/bin/sh
# Consumer-side verification only. Never builds, downloads, extracts, or runs
# the artifact. GitHub CLI retrieves attestation/trust metadata in online mode.
# Policy changes require review; do not replace these constants from a bundle.
set -eu

usage() {
    printf '%s\n' \
        'Usage: sh tier-3-verification/verify-release.sh ARTIFACT APPROVED_SOURCE_COMMIT' \
        '       sh tier-3-verification/verify-release.sh --check' \
        'ARTIFACT must be an existing readable regular file, not a symlink or URI.' \
        'APPROVED_SOURCE_COMMIT must be the independently approved lowercase 40-hex Git commit.' >&2
}

fail() {
    printf 'Verification blocked: %s\n' "$1" >&2
    exit 2
}

check_cli() {
    command -v gh >/dev/null 2>&1 || fail 'GitHub CLI (gh) is not available on PATH.'
    command -v grep >/dev/null 2>&1 || fail 'grep is required for the CLI capability check.'
    if ! cli_help=$(gh attestation verify --help 2>&1); then
        fail 'This GitHub CLI cannot describe attestation verification.'
    fi
    for required_flag in \
        --repo --hostname --signer-workflow --signer-digest \
        --source-ref --source-digest --predicate-type --cert-identity \
        --cert-oidc-issuer --deny-self-hosted-runners --digest-alg --format
    do
        if ! printf '%s\n' "$cli_help" | grep -F -e "$required_flag" >/dev/null; then
            fail 'GitHub CLI lacks a required verification policy flag; do not weaken the policy.'
        fi
    done
}

if [ "$#" -eq 1 ] && [ "$1" = '--check' ]; then
    check_cli
    gh --version
    printf '%s\n' 'Required policy flags are available. No artifact or attestation was verified.' >&2
    exit 0
fi

if [ "$#" -ne 2 ]; then
    usage
    exit 2
fi

artifact=$1
approved_commit=$2
case "$artifact" in
    ''|*://*) fail 'Supply an existing local artifact file, not a URL or OCI reference.' ;;
    /*) ;;
    *) artifact="$(pwd)/$artifact" ;;
esac

[ -f "$artifact" ] || fail 'Artifact is not a regular file.'
[ -r "$artifact" ] || fail 'Artifact is not readable.'
[ ! -L "$artifact" ] || fail 'Artifact symlinks are not accepted.'
[ "${#approved_commit}" -eq 40 ] || fail 'Approved source commit must contain exactly 40 hexadecimal characters.'
case "$approved_commit" in
    *[!0-9a-f]*) fail 'Approved source commit must be lowercase hexadecimal, not a branch or tag.' ;;
    0000000000000000000000000000000000000000) fail 'The all-zero placeholder is not an approved commit.' ;;
esac

check_cli
GH_PROMPT_DISABLED=1
export GH_PROMPT_DISABLED

# gh computes the subject digest from the file. Identity/ref/digest expectations
# are supplied by consumer policy, never learned from unverified provenance.
# exec preserves every CLI verification/error exit status for the caller's gate.
exec gh attestation verify "$artifact" \
    --hostname github.com \
    --repo KaylahBuilds/software-supply-chain-tiered-lab \
    --signer-workflow github.com/KaylahBuilds/software-supply-chain-tiered-lab/.github/workflows/release-provenance.yml \
    --cert-identity https://github.com/KaylahBuilds/software-supply-chain-tiered-lab/.github/workflows/release-provenance.yml@refs/heads/main \
    --cert-oidc-issuer https://token.actions.githubusercontent.com \
    --signer-digest "$approved_commit" \
    --source-ref refs/heads/main \
    --source-digest "$approved_commit" \
    --predicate-type https://slsa.dev/provenance/v1 \
    --deny-self-hosted-runners \
    --digest-alg sha256 \
    --format json
