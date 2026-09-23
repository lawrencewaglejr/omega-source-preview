#!/usr/bin/python3
"""Verify offline AI inputs and stage only the pinned arm64 CPU runtime/model."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


class PayloadError(Exception):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise PayloadError(code)


def directory(path: Path) -> Path:
    require(path.is_absolute() and path.resolve() == path and path.is_dir(), "AI_DIRECTORY_INVALID")
    return path


def identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


@contextmanager
def regular(path: Path, size: int | None = None):
    directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in {0, os.getuid()} and not before.st_mode & 0o022,
                "AI_FILE_METADATA_INVALID")
        require(before.st_size == size if size is not None else before.st_size <= 1024 * 1024,
                "AI_FILE_SIZE_INVALID")
        with os.fdopen(os.dup(fd), "rb") as stream:
            yield stream
        require(identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
                "AI_FILE_CHANGED")
    finally:
        os.close(fd)


def no_duplicates(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "AI_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def keys(value: object, expected: set[str]) -> None:
    require(isinstance(value, dict) and set(value) == expected, "AI_MANIFEST_KEYS_INVALID")


def object_row(row: dict, extra: set[str] = frozenset()) -> None:
    keys(row, {"size", "sha256", "url"} | extra)
    require(type(row["size"]) is int and 0 < row["size"] <= 2 * 1024**3,
            "AI_OBJECT_SIZE_INVALID")
    require(isinstance(row["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", row["sha256"])),
            "AI_OBJECT_DIGEST_INVALID")


def read_manifest(path: Path) -> tuple[dict, bytes]:
    with regular(path) as stream:
        raw = stream.read()
    require(raw.endswith(b"\n") and raw.isascii(), "AI_MANIFEST_BYTES_INVALID")
    value = json.loads(raw, object_pairs_hook=no_duplicates)
    keys(value, {"schema", "runtime", "model"})
    require(value["schema"] == "omega-ai-payload-v1", "AI_MANIFEST_SCHEMA_INVALID")
    runtime, model = value["runtime"], value["model"]
    keys(runtime, {"version", "archive", "license", "members"})
    keys(model, {"tag", "manifest", "blobs"})
    require(runtime["version"] == "0.33.3" and model["tag"] == "qwen3:1.7b", "AI_VERSION_INVALID")
    object_row(runtime["archive"])
    object_row(runtime["license"])
    require(runtime["archive"]["url"] == "https://github.com/ollama/ollama/releases/download/v0.33.3/ollama-linux-arm64.tar.zst"
            and runtime["license"]["url"] == "https://raw.githubusercontent.com/ollama/ollama/v0.33.3/LICENSE",
            "AI_RUNTIME_SOURCE_INVALID")
    object_row(model["manifest"], {"path"})
    require(model["manifest"]["path"] == "manifests/registry.ollama.ai/library/qwen3/1.7b"
            and model["manifest"]["url"] == "https://registry.ollama.ai/v2/library/qwen3/manifests/1.7b",
            "AI_MODEL_SOURCE_INVALID")
    require(isinstance(model["blobs"], list) and len(model["blobs"]) == 5, "AI_MODEL_BLOBS_INVALID")
    for blob in model["blobs"]:
        object_row(blob)
        require(blob["url"] == "https://registry.ollama.ai/v2/library/qwen3/blobs/sha256:" + blob["sha256"],
                "AI_BLOB_SOURCE_INVALID")
    digests = [row["sha256"] for row in model["blobs"]]
    require(digests == sorted(set(digests)), "AI_MODEL_BLOB_ORDER_INVALID")
    members = runtime["members"]
    require(isinstance(members, list) and 1 <= len(members) <= 100, "AI_MEMBERS_INVALID")
    by_name = {}
    for member in members:
        require(isinstance(member, dict) and member.get("type") in {"file", "symlink"}, "AI_MEMBER_TYPE_INVALID")
        keys(member, {"path", "type", "target"} if member["type"] == "symlink"
             else {"path", "type", "size", "sha256", "mode"})
        name = member["path"]
        require(isinstance(name, str) and bool(re.fullmatch(r"bin/ollama|lib/ollama/[A-Za-z0-9_.-]+", name))
                and name not in by_name, "AI_MEMBER_PATH_INVALID")
        if member["type"] == "file":
            require(type(member["size"]) is int and 0 < member["size"] <= 100 * 1024**2
                    and isinstance(member["sha256"], str)
                    and bool(re.fullmatch(r"[0-9a-f]{64}", member["sha256"]))
                    and member["mode"] in {"0644", "0755"}, "AI_MEMBER_FILE_INVALID")
        else:
            require(isinstance(member["target"], str)
                    and bool(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", member["target"]))
                    and member["target"] not in {".", ".."}, "AI_MEMBER_LINK_INVALID")
        by_name[name] = member
    require(list(by_name) == sorted(by_name) and by_name.get("bin/ollama", {}).get("mode") == "0755",
            "AI_MEMBER_MEMBERSHIP_INVALID")
    for member in members:
        seen = set()
        while member["type"] == "symlink":
            require(member["path"] not in seen, "AI_MEMBER_LINK_CYCLE")
            seen.add(member["path"])
            target = str(PurePosixPath(member["path"]).parent / member["target"])
            require(target in by_name, "AI_MEMBER_LINK_TARGET_MISSING")
            member = by_name[target]
    return value, raw


def objects(manifest: dict) -> list[dict]:
    return [manifest["runtime"]["archive"], manifest["runtime"]["license"],
            manifest["model"]["manifest"], *manifest["model"]["blobs"]]


def verify_object(cache: Path, row: dict, target: Path | None = None, mode: int = 0o600) -> None:
    with regular(cache / row["sha256"], row["size"]) as stream:
        digest = hashlib.sha256()
        output = None
        try:
            if target is not None:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                output = target.open("xb")
                target.chmod(mode)
            while block := stream.read(1024 * 1024):
                digest.update(block)
                if output:
                    output.write(block)
            require(digest.hexdigest() == row["sha256"], "AI_OBJECT_SHA256_MISMATCH")
        finally:
            if output:
                output.close()


def model_references(cache: Path, manifest: dict) -> None:
    row = manifest["model"]["manifest"]
    with regular(cache / row["sha256"], row["size"]) as stream:
        value = json.load(stream, object_pairs_hook=no_duplicates)
    require(value.get("schemaVersion") == 2 and isinstance(value.get("layers"), list),
            "AI_MODEL_MANIFEST_INVALID")
    refs = [value["config"], *value["layers"]]
    actual = sorted((r["digest"], r["size"]) for r in refs)
    expected = sorted(("sha256:" + r["sha256"], r["size"]) for r in manifest["model"]["blobs"])
    require(actual == expected, "AI_MODEL_REFERENCES_MISMATCH")


def extract_runtime(cache: Path, manifest: dict, destination: Path) -> None:
    row = manifest["runtime"]["archive"]
    wanted = {m["path"]: m for m in manifest["runtime"]["members"]}
    seen = set()
    # Hash the entire archive before the decompressor reads any bytes. Members
    # are also verified individually; tar metadata is never used to extract.
    with regular(cache / row["sha256"], row["size"]) as source:
        require(hashlib.file_digest(source, "sha256").hexdigest() == row["sha256"], "AI_ARCHIVE_SHA256_MISMATCH")
        source.seek(0)
        with subprocess.Popen(["/usr/bin/zstd", "--decompress", "--stdout", "--quiet"],
                              stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as process:
            try:
                with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
                    for entry in archive:
                        member = wanted.get(entry.name)
                        if member is None:
                            continue  # GPU files and their links are never extracted.
                        require(entry.name not in seen, "AI_ARCHIVE_DUPLICATE_MEMBER")
                        seen.add(entry.name)
                        target = destination / entry.name
                        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                        if member["type"] == "symlink":
                            require(entry.issym() and entry.linkname == member["target"], "AI_ARCHIVE_LINK_MISMATCH")
                            # Create links only after all regular files have been checked.
                            continue
                        require(entry.isfile() and not entry.islnk() and entry.size == member["size"],
                                "AI_ARCHIVE_MEMBER_MISMATCH")
                        digest = hashlib.sha256()
                        with archive.extractfile(entry) as stream, target.open("xb") as output:
                            while block := stream.read(1024 * 1024):
                                digest.update(block)
                                output.write(block)
                        require(digest.hexdigest() == member["sha256"], "AI_RUNTIME_FILE_SHA256_MISMATCH")
                        target.chmod(int(member["mode"], 8))
                # Consume tar padding so zstd can finish without a full pipe.
                while process.stdout.read(1024 * 1024):
                    pass
                require(process.wait() == 0, "AI_ARCHIVE_DECOMPRESSION_FAILED")
            except BaseException:
                process.kill()
                process.wait()
                raise
    require(seen == set(wanted), "AI_RUNTIME_MEMBERS_MISSING")
    for member in wanted.values():
        if member["type"] == "symlink":
            (destination / member["path"]).symlink_to(member["target"])


def stage(cache: Path, manifest: dict, raw: bytes, destination: Path) -> None:
    directory(destination.parent)
    require(not destination.exists() and not destination.is_symlink(), "AI_DESTINATION_EXISTS")
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "1787801458"))
    with tempfile.TemporaryDirectory(prefix=".omega-ai-", dir=destination.parent) as temporary:
        root = Path(temporary)
        runtime = root / "opt/omega-ai" / ("ollama-" + manifest["runtime"]["version"])
        extract_runtime(cache, manifest, runtime)
        verify_object(cache, manifest["runtime"]["license"], runtime / "LICENSE", 0o644)
        models = root / "var/lib/omega-ai/models"
        verify_object(cache, manifest["model"]["manifest"], models / manifest["model"]["manifest"]["path"])
        for blob in manifest["model"]["blobs"]:
            verify_object(cache, blob, models / "blobs" / ("sha256-" + blob["sha256"]))
        receipt = root / "usr/share/omega/ai/manifest.json"
        receipt.parent.mkdir(parents=True, mode=0o755)
        receipt.write_bytes(raw)
        receipt.chmod(0o644)
        for path in [*root.rglob("*"), root]:
            if path.is_dir():
                private = path == root / "var/lib/omega-ai" or root / "var/lib/omega-ai" in path.parents
                path.chmod(0o700 if private else 0o755)
            os.utime(path, (epoch, epoch), follow_symlinks=False)
        require(not destination.exists() and not destination.is_symlink(), "AI_DESTINATION_EXISTS")
        root.rename(destination)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-cache-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--stage-root", type=Path)
    args = parser.parse_args()
    manifest, raw = read_manifest(args.manifest)
    cache = directory(directory(args.input_cache_root) / "cache/objects/sha256")
    for row in objects(manifest):
        verify_object(cache, row)
    model_references(cache, manifest)
    if args.stage_root is not None:
        stage(cache, manifest, raw, args.stage_root)
        print("AI_PAYLOAD_STAGED=YES")
    print(f"AI_OBJECTS_VERIFIED={len(objects(manifest))}")
    print("AI_INPUT_CACHE=VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (PayloadError, OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
