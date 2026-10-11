"""Validate local pins, then build deterministic educational outputs."""

import argparse
from pathlib import Path

from lab.common import (ARTIFACT_NAME, DEFAULT_FIXTURES, LabError, RECORD_NAME,
                        RECORD_SCHEMA, SBOM_NAME, TRUST_NOTICE, digest, json_bytes,
                        normalized_lock, reject_links, sbom_document, validate_inputs, zip_bytes)


def build_record(components, artifact: bytes, sbom: bytes) -> dict:
    return {
        "schema": RECORD_SCHEMA, "signed": False, "trust_notice": TRUST_NOTICE,
        "lock_sha256": digest(json_bytes(normalized_lock(components))),
        "components": [component.metadata() for component in components],
        "artifact": {"name": ARTIFACT_NAME, "sha256": digest(artifact), "size_bytes": len(artifact)},
        "sbom": {"name": SBOM_NAME, "sha256": digest(sbom), "size_bytes": len(sbom)},
    }


def build(output: Path, *, fixtures: Path = DEFAULT_FIXTURES) -> dict:
    components = validate_inputs(fixtures)
    artifact = zip_bytes(components)
    sbom = json_bytes(sbom_document(components))
    record = build_record(components, artifact, sbom)
    output = Path(output).absolute()
    reject_links(output)
    output = output.resolve(strict=False)
    fixture_root = Path(fixtures).absolute()
    reject_links(fixture_root)
    fixture_root = fixture_root.resolve(strict=False)
    if output.exists():
        raise LabError("Output must be a NEW directory; the lab never overwrites existing files")
    if output.is_relative_to(fixture_root):
        raise LabError("Build outputs must stay outside fixture inputs")
    output.mkdir(parents=True, exist_ok=False)
    for name, content in ((ARTIFACT_NAME, artifact), (SBOM_NAME, sbom), (RECORD_NAME, json_bytes(record))):
        with (output / name).open("xb") as stream:
            stream.write(content)
    return record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic build; no downloads, signing, or trusted provenance")
    parser.add_argument("--output", type=Path, default=Path("artifacts"), help="New output directory")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES, help="Local fixture directory with components and lock")
    args = parser.parse_args(argv)
    try:
        record = build(args.output, fixtures=args.fixtures)
    except (LabError, OSError) as error:
        parser.exit(1, f"Build rejected: {error}\n")
    print(f"Built {ARTIFACT_NAME}: {record['artifact']['sha256']}\n{TRUST_NOTICE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
