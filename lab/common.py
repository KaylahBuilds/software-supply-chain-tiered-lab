"""Strict local fixture contracts and reproducible artifact serialization."""

from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


LOCK_SCHEMA = "lab-component-lock/v1"
RECORD_SCHEMA = "lab-build-record/v1"
TRUST_NOTICE = "Unsigned local consistency record; NOT trusted provenance, signing, or publisher authenticity"
ARTIFACT_NAME = "source.zip"
SBOM_NAME = "bom.cdx.json"
RECORD_NAME = "build-record.json"
OUTPUT_NAMES = {ARTIFACT_NAME, SBOM_NAME, RECORD_NAME}
MAX_COMPONENTS = 100
MAX_COMPONENT_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 10 * 1024 * 1024
MAX_METADATA_BYTES = 128 * 1024
ZIP_DATE = (1980, 1, 1, 0, 0, 0)
ZIP_PERMISSIONS = (stat.S_IFREG | 0o644) << 16
DEFAULT_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


class LabError(ValueError):
    """Input failed the limited, local teaching contract."""


@dataclass(frozen=True)
class Component:
    name: str
    version: str
    path: str
    sha256: str
    content: bytes = b""

    def metadata(self) -> dict:
        return {"name": self.name, "version": self.version, "path": self.path, "sha256": self.sha256}


def digest(content: bytes) -> str:
    return sha256(content).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def reject_links(path: Path) -> None:
    """Reject symlinks and Windows reparse points, including existing parents."""
    for candidate in (path, *path.parents):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        attributes = getattr(info, "st_file_attributes", 0)
        if stat.S_ISLNK(info.st_mode) or attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
            raise LabError("Symlinks and reparse points are outside this lab's input/output contract")


def read_regular(path: Path, limit: int) -> bytes:
    reject_links(path)
    if not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
        raise LabError("A required regular file is missing")
    with path.open("rb") as stream:
        content = stream.read(limit + 1)
    if len(content) > limit:
        raise LabError("Input exceeds the lab's size limit")
    return content


def load_json(content: bytes) -> object:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise LabError("Duplicate JSON keys are not allowed")
            result[key] = value
        return result

    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LabError("Metadata must be valid UTF-8 JSON") from error


def parse_components(value: object) -> tuple[Component, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_COMPONENTS:
        raise LabError("Declare a bounded, non-empty component list")
    components = []
    paths, names = set(), set()
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {"name", "version", "path", "sha256"}:
            raise LabError("Each component requires exactly name, version, path, and sha256")
        name, version, path, content_hash = (entry[key] for key in ("name", "version", "path", "sha256"))
        if not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            raise LabError("Use a synthetic lowercase component name")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            raise LabError("Use an explicit three-part synthetic component version")
        if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,159}", path):
            raise LabError("Component paths must be bounded relative POSIX paths")
        pure_path = PurePosixPath(path)
        if pure_path.is_absolute() or any(part in (".", "..") for part in pure_path.parts) or str(pure_path) != path:
            raise LabError("Path traversal and noncanonical paths are forbidden")
        if not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash):
            raise LabError("Every component needs a lowercase SHA-256 content pin")
        if path in paths or name in names:
            raise LabError("Duplicate component names or paths are forbidden")
        paths.add(path)
        names.add(name)
        components.append(Component(name, version, path, content_hash))
    return tuple(sorted(components, key=lambda component: component.path))


def validate_inputs(fixtures: Path = DEFAULT_FIXTURES) -> tuple[Component, ...]:
    fixtures = Path(fixtures).absolute()
    root = fixtures / "components"
    reject_links(root)
    if not root.is_dir():
        raise LabError("The component directory is missing")
    manifest = load_json(read_regular(fixtures / "components.lock.json", MAX_METADATA_BYTES))
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "components"} or manifest["schema"] != LOCK_SCHEMA:
        raise LabError("Unsupported or malformed lock manifest")
    declared = parse_components(manifest["components"])
    actual = set()
    for entry in root.rglob("*"):
        reject_links(entry)
        if entry.is_file():
            actual.add(entry.relative_to(root).as_posix())
        elif not entry.is_dir():
            raise LabError("Only regular files and directories are permitted")
    if actual != {component.path for component in declared}:
        raise LabError("Missing or extra component files: fixture inventory drift")
    validated, total = [], 0
    for component in declared:
        content = read_regular(root / component.path, MAX_COMPONENT_BYTES)
        total += len(content)
        if total > MAX_TOTAL_BYTES or digest(content) != component.sha256:
            raise LabError("Component content changed or exceeds the aggregate size limit")
        validated.append(Component(component.name, component.version, component.path, component.sha256, content))
    # Frozen metadata, tuple ordering, and bytes form the build snapshot. Never
    # reopen mutable input paths while serializing this approved snapshot.
    return tuple(validated)


def normalized_lock(components: tuple[Component, ...]) -> dict:
    return {"schema": LOCK_SCHEMA, "components": [component.metadata() for component in components]}


def zip_bytes(components: tuple[Component, ...]) -> bytes:
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for component in components:
            info = zipfile.ZipInfo("components/" + component.path, date_time=ZIP_DATE)
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = ZIP_PERMISSIONS
            archive.writestr(info, component.content)
    return stream.getvalue()


def sbom_document(components: tuple[Component, ...]) -> dict:
    app_ref = "lab:synthetic-greeting-demo"
    refs = ["lab:" + component.name + "@" + component.version for component in components]
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "synthetic-greeting-demo", "version": "1.0.0", "bom-ref": app_ref},
            "properties": [{"name": "lab:inventory-scope", "value": "Only locked synthetic local components; NOT a complete OS or transitive inventory"}],
        },
        "components": [
            {"type": "library", "name": component.name, "version": component.version, "bom-ref": ref,
             "hashes": [{"alg": "SHA-256", "content": component.sha256}],
             "properties": [{"name": "lab:source-path", "value": component.path}]}
            for component, ref in zip(components, refs)
        ],
        "dependencies": [{"ref": app_ref, "dependsOn": refs}] + [{"ref": ref, "dependsOn": []} for ref in refs],
    }
