"""Verify local consistency, not artifact origin, signer, or build authorization."""

import argparse
from io import BytesIO
from pathlib import Path
import re
import zipfile

from lab.build import build_record
from lab.common import (ARTIFACT_NAME, Component, LabError, MAX_COMPONENT_BYTES,
                        MAX_METADATA_BYTES, MAX_TOTAL_BYTES, OUTPUT_NAMES, RECORD_NAME,
                        RECORD_SCHEMA, SBOM_NAME, TRUST_NOTICE, ZIP_DATE, ZIP_PERMISSIONS,
                        digest, json_bytes, load_json, parse_components, read_regular,
                        reject_links, sbom_document, zip_bytes)


def verify(output: Path) -> dict:
    output = Path(output).absolute()
    reject_links(output)
    if not output.is_dir() or {entry.name for entry in output.iterdir()} != OUTPUT_NAMES:
        raise LabError("Output must contain exactly the artifact, SBOM, and unsigned record")
    record = load_json(read_regular(output / RECORD_NAME, MAX_METADATA_BYTES))
    required = {"schema", "signed", "trust_notice", "lock_sha256", "components", "artifact", "sbom"}
    if (not isinstance(record, dict) or set(record) != required or record["schema"] != RECORD_SCHEMA
            or record["signed"] is not False or record["trust_notice"] != TRUST_NOTICE):
        raise LabError("Malformed, unsupported, or misleading unsigned record")
    if not isinstance(record["lock_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", record["lock_sha256"]):
        raise LabError("The canonical lock digest must be lowercase SHA-256")
    for key, name in (("artifact", ARTIFACT_NAME), ("sbom", SBOM_NAME)):
        metadata = record[key]
        if (not isinstance(metadata, dict) or set(metadata) != {"name", "sha256", "size_bytes"}
                or metadata["name"] != name or type(metadata["size_bytes"]) is not int or metadata["size_bytes"] < 0
                or not isinstance(metadata["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"])):
            raise LabError("Artifact and SBOM metadata must use fixed names, integer sizes, and SHA-256")
    declared = parse_components(record["components"])
    artifact = read_regular(output / ARTIFACT_NAME, MAX_TOTAL_BYTES + MAX_METADATA_BYTES)
    sbom = read_regular(output / SBOM_NAME, MAX_METADATA_BYTES)
    components = []
    try:
        with zipfile.ZipFile(BytesIO(artifact)) as archive:
            members = archive.infolist()
            if [member.filename for member in members] != ["components/" + component.path for component in declared]:
                raise LabError("Archive paths/order do not match the declared component inventory")
            for member, component in zip(members, declared):
                if (member.date_time != ZIP_DATE or member.create_system != 3 or member.external_attr != ZIP_PERMISSIONS
                        or member.compress_type != zipfile.ZIP_STORED or member.file_size > MAX_COMPONENT_BYTES):
                    raise LabError("Archive metadata violates the deterministic file contract")
                content = archive.read(member)
                if digest(content) != component.sha256:
                    raise LabError("Archived component does not match the declared content pin")
                components.append(Component(component.name, component.version, component.path, component.sha256, content))
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise LabError("Artifact is not a supported deterministic ZIP") from error
    components = tuple(components)
    if artifact != zip_bytes(components):
        raise LabError("Artifact has unexpected metadata, trailing data, or serialization drift")
    if load_json(sbom) != sbom_document(components) or sbom != json_bytes(sbom_document(components)):
        raise LabError("SBOM must describe exactly the limited synthetic component inventory")
    if record != build_record(components, artifact, sbom):
        raise LabError("Artifact/SBOM digests, sizes, or canonical lock metadata do not match the unsigned record")
    return {"consistent": True, "authenticated": False, "signed": False, "trust_notice": TRUST_NOTICE}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check local digest consistency; NOT authenticity or trusted provenance")
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    args = parser.parse_args(argv)
    try:
        result = verify(args.output)
    except (LabError, OSError) as error:
        parser.exit(1, f"Consistency check rejected: {error}\n")
    print(f"Consistency checks passed. authenticated={result['authenticated']}\n{TRUST_NOTICE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
