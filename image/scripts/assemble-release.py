#!/usr/bin/python3
"""Create OMEGA release artifacts from one completed offline image build."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from typing import Any


class ReleaseError(Exception):
    pass


def require_directory(path: pathlib.Path, code: str) -> pathlib.Path:
    if not path.is_absolute():
        raise ReleaseError(f"{code}_NOT_ABSOLUTE")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode) or path.resolve() != path:
        raise ReleaseError(f"{code}_INVALID")
    return path


def require_file(path: pathlib.Path, code: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ReleaseError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{code}_INVALID")
    return path


def read_packages(path: pathlib.Path, installed_path: pathlib.Path) -> list[dict[str, Any]]:
    lines = require_file(path, "PACKAGE_MANIFEST").read_text(encoding="ascii").splitlines()
    if len(lines) < 5 or lines[0] != "omega-package-manifest-v1":
        raise ReleaseError("PACKAGE_MANIFEST_FORMAT_INVALID")
    locked: dict[tuple[str, str], dict[str, Any]] = {}
    for line in lines[4:]:
        fields = line.split("\t")
        if len(fields) != 7:
            raise ReleaseError("PACKAGE_MANIFEST_ROW_INVALID")
        name, version, architecture, _, digest, repositories, _ = fields
        identifier = re.sub(r"[^A-Za-z0-9.-]", "-", f"SPDXRef-deb-{name}-{architecture}")
        key = (name, version)
        if key in locked:
            raise ReleaseError("PACKAGE_MANIFEST_IDENTITY_AMBIGUOUS")
        locked[key] = {
            "SPDXID": identifier,
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            "supplier": "NOASSERTION",
            "sourceInfo": f"Locked package repositories: {repositories}",
            "primaryPackagePurpose": "OTHER",
        }
    installed = require_file(installed_path, "INSTALLED_PACKAGE_MANIFEST").read_text(encoding="ascii")
    if not installed or not installed.endswith("\n"):
        raise ReleaseError("INSTALLED_PACKAGE_MANIFEST_FORMAT_INVALID")
    result = []
    seen: set[tuple[str, str]] = set()
    for line in installed.splitlines():
        fields = line.split("\t")
        if len(fields) != 2:
            raise ReleaseError("INSTALLED_PACKAGE_MANIFEST_ROW_INVALID")
        key = (fields[0], fields[1])
        if key in seen:
            raise ReleaseError("INSTALLED_PACKAGE_MANIFEST_DUPLICATE")
        if key not in locked:
            raise ReleaseError(f"INSTALLED_PACKAGE_NOT_LOCKED_{fields[0]}")
        seen.add(key)
        result.append(locked[key])
    result.sort(key=lambda package: str(package["SPDXID"]))
    return result


def read_images(path: pathlib.Path) -> list[dict[str, Any]]:
    lines = require_file(path, "OCI_MANIFEST").read_text(encoding="ascii").splitlines()
    if len(lines) != 7 or lines[0] != "omega-oci-images-manifest-v1":
        raise ReleaseError("OCI_MANIFEST_FORMAT_INVALID")
    result = []
    for line in lines[5:]:
        fields = line.split("\t")
        if len(fields) != 9:
            raise ReleaseError("OCI_MANIFEST_ROW_INVALID")
        name, repository, release, _, manifest_digest = fields[:5]
        result.append({
            "SPDXID": f"SPDXRef-oci-{name}",
            "name": f"docker.io/{repository}",
            "versionInfo": release,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": manifest_digest}],
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "CONTAINER",
            "comment": "Pinned container artifact; packages inside this container have not been enumerated.",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:docker/{repository}@sha256:{manifest_digest}",
            }],
        })
    return result


def sha256(path: pathlib.Path) -> str:
    with path.open("rb") as content:
        return hashlib.file_digest(content, "sha256").hexdigest()


def copy_sparse(source: pathlib.Path, destination: pathlib.Path) -> None:
    completed = subprocess.run(
        ["/bin/cp", "--sparse=always", "--", str(source), str(destination)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise ReleaseError(f"RELEASE_COPY_FAILED_{source.name}")


def compress_image(source: pathlib.Path, destination: pathlib.Path) -> None:
    with destination.open("xb") as output:
        completed = subprocess.run(
            [
                "/usr/bin/xz", "--compress", "--stdout", "--threads=1",
                "--check=sha256", "--lzma2=preset=9e,dict=64MiB", "--", str(source),
            ],
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode != 0:
        destination.unlink(missing_ok=True)
        raise ReleaseError("IMAGE_COMPRESSION_FAILED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-root", required=True, type=pathlib.Path)
    parser.add_argument("--omega-source", required=True, type=pathlib.Path)
    parser.add_argument("--output-directory", required=True, type=pathlib.Path)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    build_root = require_directory(args.build_root, "BUILD_ROOT")
    omega_source = require_directory(args.omega_source, "OMEGA_SOURCE")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise ReleaseError("SOURCE_COMMIT_INVALID")
    output = args.output_directory
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise ReleaseError("OUTPUT_DIRECTORY_INVALID")
    require_directory(output.parent, "OUTPUT_PARENT")
    output.mkdir(mode=0o700)

    deploy = require_directory(build_root / "deploy-omega-v1", "BUILDER_DEPLOY")
    raw_image = require_file(deploy / "omega-rpi5-trixie-arm64.img", "RAW_IMAGE")
    compressed = output / "omega-rpi5-trixie-arm64-omega-v1.img.xz"
    compress_image(raw_image, compressed)
    for source in sorted(deploy.glob("*.sparse")):
        require_file(source, "SPARSE_IMAGE")
        copy_sparse(source, output / source.name)
    for name in ("image.json", "config.yaml", "manifest"):
        source = deploy / name
        if source.exists():
            require_file(source, f"BUILDER_{name.upper().replace('.', '_')}")
            if name in ("config.yaml", "image.json"):
                content = source.read_text(encoding="utf-8")
                content = content.replace(str(build_root.parent), "/build/omega-workspace")
                (output / name).write_text(content, encoding="utf-8")
            else:
                copy_sparse(source, output / name)

    packages = read_packages(omega_source / "locks/packages.manifest", deploy / "manifest")
    images = read_images(omega_source / "locks/oci-images.manifest")
    image_digest = sha256(compressed)
    image_package = {
        "SPDXID": "SPDXRef-omega-image",
        "name": "OMEGA omega-v1 Raspberry Pi 5 image",
        "versionInfo": args.source_commit,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "packageFileName": compressed.name,
        "checksums": [{"algorithm": "SHA256", "checksumValue": image_digest}],
        "supplier": "Organization: OMEGA",
        "primaryPackagePurpose": "OPERATING_SYSTEM",
    }
    omega_package = {
        "SPDXID": "SPDXRef-omega-commands",
        "name": "OMEGA control commands",
        "versionInfo": args.source_commit,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "supplier": "Organization: OMEGA",
        "primaryPackagePurpose": "APPLICATION",
    }
    dashboard_manifest = require_file(omega_source / "locks/dashboard.manifest", "DASHBOARD_MANIFEST")
    dashboard_digest = sha256(dashboard_manifest)
    copy_sparse(dashboard_manifest, output / "dashboard.manifest")
    dashboard_package = {
        "SPDXID": "SPDXRef-omega-dashboard",
        "name": "OMEGA dashboard, telemetry collection and reporting",
        "versionInfo": args.source_commit,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": dashboard_digest}],
        "supplier": "Organization: OMEGA",
        "primaryPackagePurpose": "APPLICATION",
        "comment": "dashboard.manifest identifies the exact verified application files staged in this image.",
    }
    onboarding_manifest = require_file(omega_source / "locks/onboarding.manifest", "ONBOARDING_MANIFEST")
    onboarding_digest = sha256(onboarding_manifest)
    copy_sparse(onboarding_manifest, output / "onboarding.manifest")
    onboarding_package = {
        "SPDXID": "SPDXRef-omega-onboarding",
        "name": "OMEGA guided setup and Wazuh manager mirror",
        "versionInfo": args.source_commit,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": onboarding_digest}],
        "supplier": "Organization: OMEGA",
        "primaryPackagePurpose": "APPLICATION",
        "comment": "onboarding.manifest identifies the exact verified setup application and standalone Wazuh mirror files staged in this image.",
    }
    ai_manifest = require_file(omega_source / "locks/ai.manifest.json", "AI_MANIFEST")
    ai_digest = sha256(ai_manifest)
    ai = json.loads(ai_manifest.read_bytes())
    if ai.get("schema") != "omega-ai-payload-v1":
        raise ReleaseError("AI_MANIFEST_SCHEMA_INVALID")
    copy_sparse(ai_manifest, output / "ai.manifest.json")
    ai_packages = [{
        "SPDXID": "SPDXRef-ollama-cpu-runtime",
        "name": "Ollama arm64 CPU runtime",
        "versionInfo": ai["runtime"]["version"],
        "downloadLocation": ai["runtime"]["archive"]["url"],
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": ai["runtime"]["archive"]["sha256"]}],
        "supplier": "NOASSERTION",
        "licenseDeclared": "MIT",
        "primaryPackagePurpose": "APPLICATION",
        "comment": "Checksum identifies the complete upstream archive; ai.manifest.json identifies the CPU files selected from it, their individual hashes, and their licenses. GPU directories are excluded.",
    }, {
        "SPDXID": "SPDXRef-qwen3-model",
        "name": "Qwen3 local model for Ollama",
        "versionInfo": ai["model"]["tag"],
        "downloadLocation": ai["model"]["manifest"]["url"],
        "filesAnalyzed": False,
        "checksums": [{"algorithm": "SHA256", "checksumValue": ai["model"]["manifest"]["sha256"]}],
        "supplier": "NOASSERTION",
        "primaryPackagePurpose": "FILE",
        "comment": "Manifest and every referenced blob, including the model license, are bundled. ai.manifest.json records each size and hash.",
    }]
    all_packages = [image_package, omega_package, dashboard_package, onboarding_package] + ai_packages + packages + images
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "OMEGA omega-v1 Raspberry Pi 5 image",
        "documentNamespace": f"https://omega.invalid/spdx/omega-v1/{args.source_commit}/{image_digest}",
        "comment": "Inventory of installed Debian packages, OMEGA commands, dashboard and setup applications, Wazuh mirror, offline AI runtime/model, and bundled container artifacts. Container-internal dependencies are outside this inventory's scope.",
        "creationInfo": {
            "created": "2026-08-27T03:30:58Z",
            "creators": ["Organization: OMEGA"],
        },
        "packages": all_packages,
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-omega-image",
        }] + [
            {
                "spdxElementId": "SPDXRef-omega-image",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": package["SPDXID"],
            }
            for package in all_packages[1:]
        ],
    }
    (output / "omega-v1.spdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    provenance = {
        "schema": "omega-image-provenance-v1",
        "source_commit": args.source_commit,
        "builder_commit": "262d4df5a9f9d4133370465399a7958a7c22cdc7",
        "builder_config_plan_sha256": "c3f8efcccbed085eb6c38334e19568389e730641eb25bcca81a4dfd93cba796f",
        "package_manifest_sha256": sha256(omega_source / "locks/packages.manifest"),
        "installed_package_manifest_sha256": sha256(deploy / "manifest"),
        "oci_manifest_sha256": sha256(omega_source / "locks/oci-images.manifest"),
        "dashboard_manifest_sha256": dashboard_digest,
        "onboarding_manifest_sha256": onboarding_digest,
        "ai_manifest_sha256": ai_digest,
        "network_mode": "isolated-loopback-only",
    }
    (output / "omega-v1.provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    for path in output.iterdir():
        if path.is_file():
            os.chmod(path, 0o644)
    checksum_rows = [f"{sha256(path)}  {path.name}" for path in sorted(output.iterdir()) if path.is_file()]
    (output / "SHA256SUMS").write_text("\n".join(checksum_rows) + "\n", encoding="ascii")
    os.chmod(output / "SHA256SUMS", 0o644)
    print(f"RELEASE_OUTPUT={output}")
    print(f"RELEASE_ARTIFACTS={len(checksum_rows)}")
    print("RELEASE_ASSEMBLY=PASS")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ReleaseError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
