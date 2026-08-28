#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.metadata
import json
import subprocess
from pathlib import Path
from urllib.parse import quote


def _component(ecosystem: str, name: str, version: str, purl: str) -> dict:
    return {
        "type": "library",
        "group": ecosystem,
        "name": name,
        "version": version,
        "purl": purl,
    }


def python_components() -> list[dict]:
    components = []
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata.get("Name") or "").strip()
        version = (distribution.version or "").strip()
        if not name or not version:
            continue
        normalized = name.lower().replace("_", "-")
        purl = f"pkg:pypi/{quote(normalized, safe='')}@{quote(version, safe='')}"
        components.append(_component("python", name, version, purl))
    return components


def debian_components() -> list[dict]:
    result = subprocess.run(
        ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\n"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    components = []
    for line in result.stdout.splitlines():
        name, separator, version = line.partition("\t")
        if not separator or not name or not version:
            continue
        purl = f"pkg:deb/debian/{quote(name, safe='')}@{quote(version, safe='')}"
        components.append(_component("debian", name, version, purl))
    return components


def npm_components(package_lock: Path) -> list[dict]:
    try:
        lock = json.loads(package_lock.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read npm lockfile: {exc}") from exc
    components = []
    for package_path, record in lock.get("packages", {}).items():
        if not package_path.startswith("node_modules/") or not isinstance(record, dict):
            continue
        name = package_path.removeprefix("node_modules/")
        version = str(record.get("version") or "").strip()
        if not name or not version:
            continue
        purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"
        components.append(_component("npm", name, version, purl))
    return components


def model_component(provenance_path: Path | None) -> dict | None:
    if provenance_path is None:
        return None
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        repository = provenance["repository"]
        revision = provenance["revision"]
        model_sha256 = provenance["model_sha256"]
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read model provenance: {exc}") from exc
    if not all(isinstance(value, str) and value for value in (repository, revision, model_sha256)):
        raise SystemExit("Model provenance is invalid")
    return {
        "type": "machine-learning-model",
        "group": "huggingface",
        "name": repository,
        "version": revision,
        "purl": f"pkg:huggingface/{quote(repository, safe='/')}@{quote(revision, safe='')}",
        "hashes": [{"alg": "SHA-256", "content": model_sha256}],
    }


def tool_component(specification: str) -> dict:
    try:
        name, version, sha256, purl = specification.split("|", 3)
    except ValueError as exc:
        raise SystemExit("Tool provenance must be name|version|sha256|purl") from exc
    if (
        not name
        or not version
        or len(sha256) != 64
        or any(character not in "0123456789abcdef" for character in sha256)
        or not purl.startswith("pkg:")
    ):
        raise SystemExit("Tool provenance is invalid")
    return {
        "type": "application",
        "group": "runtime-tool",
        "name": name,
        "version": version,
        "purl": purl,
        "hashes": [{"alg": "SHA-256", "content": sha256}],
    }


def build_sbom(
    package_lock: Path,
    application_version: str,
    model_provenance: Path | None = None,
    tools: list[str] | None = None,
) -> dict:
    model = model_component(model_provenance)
    inventory = [*python_components(), *debian_components(), *npm_components(package_lock)]
    if model is not None:
        inventory.append(model)
    inventory.extend(tool_component(specification) for specification in tools or [])
    by_purl = {
        component["purl"]: component
        for component in inventory
    }
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "hermes-railway-runtime",
                "version": application_version,
            }
        },
        "components": [by_purl[purl] for purl in sorted(by_purl)],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--package-lock", type=Path, required=True)
    parser.add_argument("--application-version", required=True)
    parser.add_argument("--model-provenance", type=Path)
    parser.add_argument("--tool", action="append", default=[])
    args = parser.parse_args()
    sbom = build_sbom(args.package_lock, args.application_version, args.model_provenance, args.tool)
    args.output.write_text(
        json.dumps(sbom, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
