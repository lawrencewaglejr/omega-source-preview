#!/usr/bin/python3
"""Run and verify the pinned rpi-image-gen configuration pipeline."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import stat
import subprocess
import sys


class ValidationError(Exception):
    pass


def require_directory(path: pathlib.Path, code: str) -> pathlib.Path:
    if not path.is_absolute():
        raise ValidationError(f"{code}_NOT_ABSOLUTE")
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValidationError(f"{code}_INVALID")
    if path.resolve() != path:
        raise ValidationError(f"{code}_NOT_CANONICAL")
    return path


def require_regular_file(path: pathlib.Path, code: str) -> pathlib.Path:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise ValidationError(f"{code}_MISSING") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValidationError(f"{code}_INVALID")
    return path


def read_lock(path: pathlib.Path) -> dict[str, str]:
    require_regular_file(path, "BUILDER_LOCK")
    values: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        if not line or ": " not in line:
            raise ValidationError(f"BUILDER_LOCK_LINE_INVALID_{line_number}")
        key, value = line.split(": ", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in values:
            raise ValidationError(f"BUILDER_LOCK_LINE_INVALID_{line_number}")
        values[key] = value
    return values


def read_assignments(path: pathlib.Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "=" not in stripped:
            raise ValidationError(f"CONFIG_ENV_LINE_INVALID_{line_number}")
        key, value = stripped.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValidationError(f"CONFIG_ENV_KEY_INVALID_{line_number}")
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        result[key] = value
    return result


def run_engine(
    engine: pathlib.Path,
    arguments: list[str],
    environment: dict[str, str],
    *,
    output: pathlib.Path | None = None,
) -> str:
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(engine), *arguments],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise ValidationError("BUILDER_CONFIG_ENGINE_TIMEOUT") from exc
    if output is not None:
        output.write_text(completed.stdout, encoding="utf-8")
    if completed.returncode != 0:
        tail = completed.stdout.replace("\n", "|")[-1000:]
        raise ValidationError(f"BUILDER_CONFIG_ENGINE_FAILED_{completed.returncode}:{tail}")
    return completed.stdout


def assert_network_namespace(host_namespace: str) -> str:
    if not re.fullmatch(r"net:\[[0-9]+\]", host_namespace):
        raise ValidationError("HOST_NETWORK_NAMESPACE_INVALID")
    current = os.readlink("/proc/self/ns/net")
    if current == host_namespace:
        raise ValidationError("CONFIG_NETWORK_NAMESPACE_NOT_ISOLATED")
    devices = pathlib.Path("/proc/net/dev").read_text(encoding="ascii").splitlines()[2:]
    interfaces = {line.split(":", 1)[0].strip() for line in devices if ":" in line}
    if interfaces != {"lo"}:
        raise ValidationError("CONFIG_NETWORK_NAMESPACE_HAS_EXTERNAL_INTERFACE")
    routes = pathlib.Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    if any(line.strip() for line in routes):
        raise ValidationError("CONFIG_NETWORK_NAMESPACE_HAS_IPV4_ROUTE")
    return current


def layer_paths(builder_root: pathlib.Path, omega_root: pathlib.Path, dynamic: pathlib.Path) -> str:
    parts = [f"DYNlayer={dynamic}"]
    for tag, relative in (("SRCdevice", "device"), ("SRCimage", "image"), ("SRClayer", "layer")):
        candidate = omega_root / relative
        if candidate.is_dir():
            parts.append(f"{tag}={candidate}")
    parts.extend(
        (
            f"IGdevice={builder_root / 'device'}",
            f"IGimage={builder_root / 'image'}",
            f"IGlayer={builder_root / 'layer'}",
        )
    )
    return ":".join(parts)


def normalized_plan(
    plan_path: pathlib.Path,
    builder_root: pathlib.Path,
    omega_root: pathlib.Path,
    workspace: pathlib.Path,
) -> tuple[bytes, list[tuple[str, str, str, str]]]:
    raw_lines = plan_path.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str, str, str]] = []
    output: list[str] = []
    replacements = (
        (str(builder_root), "@BUILDER"),
        (str(omega_root), "@OMEGA"),
        (str(workspace), "@WORK"),
    )
    for line_number, line in enumerate(raw_lines, 1):
        fields = line.split(":", 3)
        if len(fields) != 4 or not all(fields):
            raise ValidationError(f"BUILDER_PLAN_LINE_INVALID_{line_number}")
        normalized_fields: list[str] = []
        for field in fields:
            for original, replacement in replacements:
                field = field.replace(original, replacement)
            normalized_fields.append(field)
        entry = tuple(normalized_fields)
        entries.append(entry)  # type: ignore[arg-type]
        output.append(":".join(entry))
    return ("\n".join(output) + "\n").encode("utf-8"), entries


def validate_contract(assignments: dict[str, str], entries: list[tuple[str, str, str, str]]) -> None:
    expected = {
        "ARCH": "arm64",
        "SOURCE_DATE_EPOCH": "1787801458",
        "DEB_BUILD_ARCH": "arm64",
        "DEB_HOST_ARCH": "arm64",
        "TOOLCHAIN_MODE": "native",
        "IGconf_sys_workroot": "/build/omega",
        "IGconf_device_layer": "rpi5",
        "IGconf_device_class": "pi5",
        "IGconf_device_storage_type": "sd",
        "IGconf_device_hostname": "omega",
        "IGconf_device_user1sudo": "passwd",
        "IGconf_image_layer": "image-rpios",
        "IGconf_image_boot_part_size": "512M",
        "IGconf_image_root_part_size": "31G",
        "IGconf_image_name": "omega-rpi5-trixie-arm64",
        "IGconf_image_rootfs_type": "ext4",
        "IGconf_image_pmap": "clear",
        "IGconf_image_disksig": "0xbd67750e",
        "IGconf_fs_ext4_mkfs_args": "-F -b 16384 -E hash_seed=bd67750e-9777-5c69-b79e-ee0d454fbe92",
        "IGconf_image_suffix": "img",
        "IGconf_image_provider": "genimage",
        "IGconf_deploy_compression": "none",
        "IGconf_sbom_enable": "n",
        "IGconf_locale_default": "C.UTF-8",
        "IGconf_locale_timezone": "UTC",
        "IGconf_artefact_version": "omega-v1",
    }
    for key, value in expected.items():
        if assignments.get(key) != value:
            raise ValidationError(f"BUILDER_CONFIG_VALUE_MISMATCH_{key}")
    for key, value in assignments.items():
        if "$(" in value or "`" in value:
            raise ValidationError(f"BUILDER_CONFIG_SHELL_EXPANSION_{key}")

    versions = {name: version for name, version, _, _ in entries}
    required = {
        "essential": "2.0.0",
        "rpi5": "3.0.0",
        "image-rpios": "2.3.0",
        "omega-debian-trixie-arm64": "1.0.0",
        "omega-services": "1.0.0",
        "omega-trixie-minbase": "1.0.0",
    }
    for layer, version in required.items():
        if versions.get(layer) != version:
            raise ValidationError(f"BUILDER_PLAN_REQUIRED_LAYER_MISMATCH_{layer}")
    forbidden = {
        "image-rpios-ab",
        "debian-trixie-arm64-minbase-snapshot",
        "debian-trixie-arm64-multi",
        "rpi-debian-trixie",
        "trixie-minbase",
    }
    if forbidden.intersection(versions):
        raise ValidationError("BUILDER_PLAN_FORBIDDEN_LAYER")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--builder-root", required=True, type=pathlib.Path)
    parser.add_argument("--omega-image-root", required=True, type=pathlib.Path)
    parser.add_argument("--workspace", required=True, type=pathlib.Path)
    parser.add_argument("--lock", required=True, type=pathlib.Path)
    parser.add_argument("--host-network-namespace", required=True)
    args = parser.parse_args()

    builder_root = require_directory(args.builder_root, "BUILDER_ROOT")
    omega_root = require_directory(args.omega_image_root, "OMEGA_IMAGE_ROOT")
    workspace = require_directory(args.workspace, "CONFIG_WORKSPACE")
    lock = read_lock(args.lock)
    current_namespace = assert_network_namespace(args.host_network_namespace)

    engine = require_regular_file(builder_root / "bin/ig", "BUILDER_CONFIG_ENGINE")
    config = require_regular_file(
        omega_root / "config/omega-rpi5-trixie-arm64.yaml", "OMEGA_IMAGE_CONFIG"
    )
    registry = require_regular_file(builder_root / "registry.defs", "BUILDER_REGISTRY")
    dynamic = workspace / "dynamic/layer"
    dynamic.mkdir(parents=True, mode=0o700)

    environment = {
        "PATH": f"{builder_root / 'bin'}:{builder_root / 'bin/generators'}:/usr/bin:/bin",
        "HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    registry_output = run_engine(engine, ["metadata", "--emit", str(registry)], environment)
    registry_env = workspace / "registry.env"
    registry_env.write_text(registry_output, encoding="utf-8")

    user_env = workspace / "user.env"
    run_engine(
        engine,
        [
            "config",
            "--path",
            f"{config.parent}:{builder_root / 'config'}",
            str(config),
            "--write-to",
            str(user_env),
        ],
        environment,
        output=workspace / "config.log",
    )
    user_assignments = read_assignments(user_env)
    layers = ["essential"]
    for key, value in user_assignments.items():
        if key in {"IGconf_device_layer", "IGconf_image_layer"} or key.startswith("IGconf_layer_"):
            layers.append(value)

    config_env = workspace / "config.env"
    config_env.write_text(
        registry_env.read_text(encoding="utf-8")
        + user_env.read_text(encoding="utf-8")
        + "".join(
            f'{key}="{value}"\n'
            for key, value in (
                ("DEB_BUILD_ARCH", "arm64"),
                ("DEB_BUILD_GNU_TYPE", "aarch64-linux-gnu"),
                ("DEB_HOST_ARCH", "arm64"),
                ("DEB_HOST_GNU_TYPE", "aarch64-linux-gnu"),
                ("TOOLCHAIN_MODE", "native"),
                ("IGTOP", str(builder_root)),
                ("IGROOT", str(builder_root)),
                ("LAYER_HOOKS", str(builder_root / "layer-hooks")),
                ("RPI_TEMPLATES", str(builder_root / "templates/rpi")),
                ("DYNROOT", str(workspace / "dynamic")),
                ("SRCROOT", str(omega_root)),
            )
        ),
        encoding="utf-8",
    )

    final_env = workspace / "final.env"
    plan = workspace / "layer.plan"
    run_engine(
        engine,
        [
            "pipeline",
            "--env-in",
            str(config_env),
            "--layers",
            *layers,
            "--path",
            layer_paths(builder_root, omega_root, dynamic),
            "--env-out",
            str(final_env),
            "--plan-out",
            str(plan),
        ],
        environment,
        output=workspace / "pipeline.log",
    )

    normalized, entries = normalized_plan(plan, builder_root, omega_root, workspace)
    plan_digest = hashlib.sha256(normalized).hexdigest()
    try:
        expected_count = int(lock["builder_config_plan_entry_count"])
        expected_digest = lock["builder_config_plan_sha256"]
    except (KeyError, ValueError) as exc:
        raise ValidationError("BUILDER_CONFIG_LOCK_FIELDS_INVALID") from exc
    if len(entries) != expected_count:
        raise ValidationError("BUILDER_CONFIG_PLAN_ENTRY_COUNT_MISMATCH")
    if plan_digest != expected_digest:
        raise ValidationError("BUILDER_CONFIG_PLAN_SHA256_MISMATCH")
    validate_contract(read_assignments(final_env), entries)

    print(f"CONFIG_NETWORK_NAMESPACE={current_namespace}")
    print("CONFIG_NETWORK_ISOLATION=VERIFIED")
    print("BUILDER_CONFIG_ENGINE=bin/ig")
    print(f"BUILDER_CONFIG_PLAN_ENTRIES={len(entries)}")
    print(f"BUILDER_CONFIG_PLAN_SHA256={plan_digest}")
    print("BUILDER_CONFIG_COMPATIBILITY=VERIFIED-LOCAL-PLAN")
    print("BUILDER_CODE_EXECUTED=CONFIG-METADATA-AND-PIPELINE-ONLY")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, UnicodeError, ValidationError) as error:
        print(f"CONFIG_CHECK_ERROR={error}", file=sys.stderr)
        raise SystemExit(1)
