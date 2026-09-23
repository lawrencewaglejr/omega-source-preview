#!/usr/bin/python3
import argparse
import base64
import binascii
import errno
import hashlib
import os
import pathlib
import posixpath
import shutil
import stat
import sys
import tarfile
from dataclasses import dataclass

PROJECT = "rpi-image-gen"
RELEASE_LABEL = "v2.8.0"
TAG_ROLE = "informational-only-not-a-trust-anchor"
COMMIT = "262d4df5a9f9d4133370465399a7958a7c22cdc7"
TREE = "b4d841718ae5436dd17ed7712cec47d010853ccd"
ARCHIVE_SHA256 = "5fb1d564d9cbe0064310e1a2123bfaa0782d7010c2545c38383020cf353321ca"
ARCHIVE_RELATIVE = "cache/objects/sha256/" + ARCHIVE_SHA256
MANIFEST_RELATIVE = "locks/builder-tree.manifest"
MANIFEST_SHA256 = "8a481d1bc3e2dc5fcc47ae0783f61d6c9a9ec67f52d57e262885bfa810065114"
ARCHIVE_ROOT = "rpi-image-gen-" + COMMIT
EXPECTED_POLICY = {
    "name": PROJECT,
    "upstream_release": RELEASE_LABEL,
    "upstream_commit": COMMIT,
    "upstream_tree": TREE,
    "source_archive_sha256": ARCHIVE_SHA256,
    "builder_archive_cache_relative_path": ARCHIVE_RELATIVE,
    "builder_tree_manifest_path": MANIFEST_RELATIVE,
    "builder_tree_manifest_sha256": MANIFEST_SHA256,
    "builder_release_tag_role": TAG_ROLE,
    "builder_archive_owner_policy": "invoking-uid-or-root",
    "builder_archive_permissions_policy": "not-group-or-world-writable",
    "builder_archive_link_policy": "exactly-one",
    "builder_archive_validation_policy": "complete-before-extraction",
    "builder_evidence_runtime_role": "audit-traceability-not-runtime-input",
    "release_authentication": "operationally-approved-by-human-risk-acceptance",
    "future_mismatch_policy": "fail-closed",
}
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TOTAL_CONTENT_BYTES = 512 * 1024 * 1024


class ValidationError(RuntimeError):
    pass


def fail(code):
    raise ValidationError(code)


def sha256_stream(handle):
    digest = hashlib.sha256()
    handle.seek(0)
    for block in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(block)
    handle.seek(0)
    return digest.hexdigest()


def git_oid(kind, data):
    prefix = kind.encode("ascii") + b" " + str(len(data)).encode("ascii") + b"\0"
    return hashlib.sha1(prefix + data).hexdigest()


def reject_text_bytes(data, label, allow_tab=False):
    if not data.endswith(b"\n"):
        fail(label + "_FINAL_NEWLINE")
    for value in data:
        if value == 10 or (allow_tab and value == 9):
            continue
        if value < 32 or value == 127:
            fail(label + "_CONTROL_CHARACTER")


def require_absolute_canonical_directory(path, label):
    path = pathlib.Path(path)
    if not path.is_absolute():
        fail(label + "_NOT_ABSOLUTE")
    current = pathlib.Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            fail(label + "_MISSING")
        if stat.S_ISLNK(metadata.st_mode):
            fail(label + "_SYMLINK_COMPONENT")
        if not stat.S_ISDIR(metadata.st_mode):
            fail(label + "_NON_DIRECTORY_COMPONENT")
    if pathlib.Path(os.path.realpath(path)) != path:
        fail(label + "_NONCANONICAL")
    metadata = os.lstat(path)
    if metadata.st_uid not in (0, os.getuid()):
        fail(label + "_OWNER")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        fail(label + "_PERMISSIONS_UNSAFE")
    return path


def metadata_identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


class PinnedRegularFile:
    def __init__(self, path, label, descriptor, metadata):
        self.path = pathlib.Path(path)
        self.label = label
        self.handle = os.fdopen(descriptor, "rb", closefd=True)
        self.metadata = metadata

    def verify_stable(self):
        current_metadata = require_regular_no_symlinks(self.path, self.label)
        if (current_metadata.st_dev, current_metadata.st_ino) != (
            self.metadata.st_dev,
            self.metadata.st_ino,
        ):
            fail(self.label + "_INODE_REPLACED")
        descriptor_metadata = os.fstat(self.handle.fileno())
        if (
            metadata_identity(current_metadata) != metadata_identity(self.metadata)
            or metadata_identity(descriptor_metadata) != metadata_identity(self.metadata)
        ):
            fail(self.label + "_METADATA_CHANGED")

    def close(self):
        self.handle.close()


def open_regular_descriptor(path, label):
    path = pathlib.Path(path)
    if not path.is_absolute():
        fail(label + "_NOT_ABSOLUTE")
    if any(component in ("", ".", "..") for component in path.parts[1:]):
        fail(label + "_NONCANONICAL")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    current_descriptor = os.open(path.anchor, flags | os.O_DIRECTORY)
    final_descriptor = None
    try:
        for index, component in enumerate(path.parts[1:], start=1):
            component_flags = flags
            if index < len(path.parts) - 1:
                component_flags |= os.O_DIRECTORY
            try:
                next_descriptor = os.open(component, component_flags, dir_fd=current_descriptor)
            except FileNotFoundError:
                fail(label + "_MISSING")
            except NotADirectoryError:
                try:
                    component_metadata = os.stat(
                        component, dir_fd=current_descriptor, follow_symlinks=False
                    )
                except OSError:
                    fail(label + "_NON_DIRECTORY_COMPONENT")
                if stat.S_ISLNK(component_metadata.st_mode):
                    fail(label + "_SYMLINK_COMPONENT")
                fail(label + "_NON_DIRECTORY_COMPONENT")
            except OSError as error:
                if error.errno == errno.ELOOP:
                    fail(label + "_SYMLINK_COMPONENT")
                fail(label + "_OPEN_FAILED")
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        final_descriptor = current_descriptor
        current_descriptor = None
        metadata = os.fstat(final_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail(label + "_NOT_REGULAR")
        if pathlib.Path(os.path.realpath(path)) != path:
            fail(label + "_NONCANONICAL")
        path_metadata = os.lstat(path)
        if metadata_identity(path_metadata) != metadata_identity(metadata):
            fail(label + "_INODE_REPLACED")
        descriptor = final_descriptor
        final_descriptor = None
        return path, descriptor, metadata
    finally:
        if current_descriptor is not None:
            os.close(current_descriptor)
        if final_descriptor is not None:
            os.close(final_descriptor)


def require_regular_no_symlinks(path, label):
    _, descriptor, metadata = open_regular_descriptor(path, label)
    try:
        return metadata
    finally:
        os.close(descriptor)


def open_pinned_regular(path, label):
    path, descriptor, metadata = open_regular_descriptor(path, label)
    return PinnedRegularFile(path, label, descriptor, metadata)


def parse_lock(path):
    pinned = open_pinned_regular(path, "BUILDER_LOCK")
    try:
        if pinned.metadata.st_size > 128 * 1024:
            fail("BUILDER_LOCK_TOO_LARGE")
        data = pinned.handle.read(128 * 1024 + 1)
        if len(data) > 128 * 1024:
            fail("BUILDER_LOCK_TOO_LARGE")
        pinned.verify_stable()
    finally:
        pinned.close()
    reject_text_bytes(data, "BUILDER_LOCK")
    try:
        text = data.decode("ascii", "strict")
    except UnicodeDecodeError:
        fail("BUILDER_LOCK_NON_ASCII")
    values = {}
    for number, line in enumerate(text.splitlines(), start=1):
        if ": " not in line:
            fail("BUILDER_LOCK_MALFORMED_LINE_" + str(number))
        key, value = line.split(": ", 1)
        if not key or not value or key in values:
            fail("BUILDER_LOCK_DUPLICATE_OR_EMPTY")
        values[key] = value
    for key, expected in EXPECTED_POLICY.items():
        if values.get(key) != expected:
            fail("BUILDER_LOCK_POLICY_MISMATCH_" + key.upper())
    return values


def validate_relative_path(value, label):
    if not value:
        fail(label + "_EMPTY")
    if value.startswith("/"):
        fail(label + "_ABSOLUTE")
    if "\\" in value:
        fail(label + "_BACKSLASH")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        fail(label + "_CONTROL_CHARACTER")
    components = value.split("/")
    if any(component in ("", ".", "..") for component in components):
        fail(label + "_COMPONENT")
    return components


@dataclass(frozen=True)
class ManifestEntry:
    mode: str
    kind: str
    oid: str
    size: int
    path: str
    target: str | None


@dataclass(frozen=True)
class Manifest:
    entries: dict
    root_tree: str
    archive_root: str


def parse_manifest(path, policy):
    pinned = open_pinned_regular(path, "BUILDER_MANIFEST")
    try:
        if pinned.metadata.st_size <= 0 or pinned.metadata.st_size > MAX_MANIFEST_BYTES:
            fail("BUILDER_MANIFEST_SIZE")
        data = pinned.handle.read(MAX_MANIFEST_BYTES + 1)
        if len(data) > MAX_MANIFEST_BYTES:
            fail("BUILDER_MANIFEST_SIZE")
        pinned.verify_stable()
    finally:
        pinned.close()
    if hashlib.sha256(data).hexdigest() != policy["builder_tree_manifest_sha256"]:
        fail("BUILDER_MANIFEST_SHA256_MISMATCH")
    reject_text_bytes(data, "BUILDER_MANIFEST", allow_tab=True)
    try:
        lines = data.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError:
        fail("BUILDER_MANIFEST_UTF8")
    expected_header = [
        "omega-builder-tree-manifest-v1",
        "project\t" + PROJECT,
        "release_label\t" + RELEASE_LABEL,
        "release_tag_role\t" + TAG_ROLE,
        "commit\t" + COMMIT,
        "root_tree\t" + TREE,
        "archive_sha256\t" + ARCHIVE_SHA256,
        "archive_top_level\t" + ARCHIVE_ROOT,
    ]
    if lines[:8] != expected_header:
        fail("BUILDER_MANIFEST_HEADER")
    if len(lines) < 10 or not lines[8].startswith("entry_count\t"):
        fail("BUILDER_MANIFEST_ENTRY_COUNT_HEADER")
    try:
        declared_count = int(lines[8].split("\t", 1)[1])
    except ValueError:
        fail("BUILDER_MANIFEST_ENTRY_COUNT")
    if lines[9] != "mode\ttype\toid\tsize\tpath\ttarget_base64":
        fail("BUILDER_MANIFEST_COLUMNS")
    entries = {}
    prior_path = None
    for line in lines[10:]:
        fields = line.split("\t")
        if len(fields) != 6:
            fail("BUILDER_MANIFEST_ROW")
        mode, kind, oid, size_text, entry_path, target_field = fields
        components = validate_relative_path(entry_path, "BUILDER_MANIFEST_PATH")
        if any(component == ".git" for component in components):
            fail("BUILDER_MANIFEST_GIT_CONTENT")
        if ".gitmodules" in components:
            fail("BUILDER_MANIFEST_GITMODULES")
        if prior_path is not None and entry_path.encode("utf-8") <= prior_path.encode("utf-8"):
            fail("BUILDER_MANIFEST_ORDER_OR_DUPLICATE")
        prior_path = entry_path
        if not len(oid) == 40 or any(ch not in "0123456789abcdef" for ch in oid):
            fail("BUILDER_MANIFEST_OID")
        try:
            size = int(size_text)
        except ValueError:
            fail("BUILDER_MANIFEST_SIZE_FIELD")
        if size < 0 or size > MAX_TOTAL_CONTENT_BYTES:
            fail("BUILDER_MANIFEST_SIZE_FIELD")
        target = None
        if mode == "040000" and kind == "tree":
            if size != 0 or target_field != "-":
                fail("BUILDER_MANIFEST_TREE_ROW")
        elif mode in ("100644", "100755") and kind == "blob":
            if target_field != "-":
                fail("BUILDER_MANIFEST_FILE_ROW")
        elif mode == "120000" and kind == "blob":
            try:
                raw_target = base64.b64decode(target_field, validate=True)
                target = raw_target.decode("utf-8", "strict")
            except (binascii.Error, UnicodeDecodeError):
                fail("BUILDER_MANIFEST_SYMLINK_TARGET")
            validate_symlink_target(entry_path, target, None)
            if size != len(raw_target) or git_oid("blob", raw_target) != oid:
                fail("BUILDER_MANIFEST_SYMLINK_BLOB")
        else:
            fail("BUILDER_MANIFEST_MODE")
        entries[entry_path] = ManifestEntry(mode, kind, oid, size, entry_path, target)
    if declared_count != len(entries):
        fail("BUILDER_MANIFEST_ENTRY_COUNT_MISMATCH")
    for entry_path in entries:
        if "/" in entry_path:
            parent = entry_path.rsplit("/", 1)[0]
            if parent not in entries or entries[parent].mode != "040000":
                fail("BUILDER_MANIFEST_PARENT_MISSING")
    return Manifest(entries, TREE, ARCHIVE_ROOT)


def validate_symlink_target(path, target, entries):
    if not target:
        fail("SYMLINK_TARGET_EMPTY")
    if target.startswith("/"):
        fail("SYMLINK_TARGET_ABSOLUTE")
    if "\\" in target or any(ord(ch) < 32 or ord(ch) == 127 for ch in target):
        fail("SYMLINK_TARGET_UNSAFE")
    combined = posixpath.normpath(posixpath.join(posixpath.dirname(path), target))
    if combined in ("", ".", "..") or combined.startswith("../") or combined.startswith("/"):
        fail("SYMLINK_TARGET_ESCAPE")
    if entries is not None and combined not in entries:
        fail("SYMLINK_TARGET_MISSING")
    return combined


def resolve_symlink_chain(path, entries):
    entry = entries[path]
    current = validate_symlink_target(path, entry.target, entries)
    visited = {path}
    for _ in range(len(entries) + 1):
        components = current.split("/")
        substituted = False
        for index in range(1, len(components) + 1):
            prefix = "/".join(components[:index])
            candidate = entries.get(prefix)
            if candidate is not None and candidate.mode == "120000":
                if prefix in visited:
                    fail("SYMLINK_CHAIN_LOOP")
                visited.add(prefix)
                remainder = "/".join(components[index:])
                target = validate_symlink_target(prefix, candidate.target, entries)
                current = target if not remainder else posixpath.normpath(target + "/" + remainder)
                if current.startswith("../") or current.startswith("/"):
                    fail("SYMLINK_CHAIN_ESCAPE")
                substituted = True
                break
        if not substituted:
            if current not in entries:
                fail("SYMLINK_CHAIN_TARGET_MISSING")
            return
    fail("SYMLINK_CHAIN_DEPTH")


def normalized_archive_path(name):
    if not name:
        fail("ARCHIVE_PATH_EMPTY")
    if name.startswith("/"):
        fail("ARCHIVE_PATH_ABSOLUTE")
    if "\\" in name:
        fail("ARCHIVE_PATH_BACKSLASH")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        fail("ARCHIVE_PATH_CONTROL_CHARACTER")
    components = name.split("/")
    if any(component in ("", ".", "..") for component in components):
        fail("ARCHIVE_PATH_COMPONENT")
    return "/".join(components)


def reconstruct_trees(entries):
    children = {"": []}
    for path, entry in entries.items():
        parent = path.rsplit("/", 1)[0] if "/" in path else ""
        children.setdefault(parent, []).append((path.rsplit("/", 1)[-1], path, entry))
        if entry.mode == "040000":
            children.setdefault(path, [])
    computed = {}
    def visit(directory):
        records = []
        for name, path, entry in children.get(directory, []):
            oid = visit(path) if entry.mode == "040000" else entry.oid
            sort_key = name.encode("utf-8") + (b"/" if entry.mode == "040000" else b"")
            records.append((sort_key, name.encode("utf-8"), entry, oid))
        body = b""
        for _, name_bytes, entry, oid in sorted(records, key=lambda row: row[0]):
            git_mode = "40000" if entry.mode == "040000" else entry.mode
            body += git_mode.encode("ascii") + b" " + name_bytes + b"\0" + bytes.fromhex(oid)
        value = git_oid("tree", body)
        computed[directory] = value
        return value
    return visit(""), computed


def validate_archive_stream(stream, manifest):
    seen = set()
    actual = {}
    data_by_path = {}
    total = 0
    try:
        stream.seek(0)
        handle = tarfile.open(fileobj=stream, mode="r:gz")
    except (tarfile.TarError, OSError):
        fail("ARCHIVE_FORMAT")
    with handle:
        members = handle.getmembers()
        if len(members) != len(manifest.entries) + 1:
            # Continue for precise missing/untracked diagnostics when possible.
            pass
        for member in members:
            name = normalized_archive_path(member.name)
            if name in seen:
                fail("ARCHIVE_DUPLICATE_PATH")
            seen.add(name)
            if name == manifest.archive_root:
                if not member.isdir() or member.mode != 0o775:
                    fail("ARCHIVE_ROOT_ENTRY")
                continue
            prefix = manifest.archive_root + "/"
            if not name.startswith(prefix):
                fail("ARCHIVE_UNEXPECTED_ROOT")
            relative = name[len(prefix):]
            components = validate_relative_path(relative, "ARCHIVE_PATH")
            if any(component == ".git" for component in components):
                fail("ARCHIVE_GIT_CONTENT")
            if ".gitmodules" in components:
                fail("ARCHIVE_GITMODULES")
            if member.islnk():
                fail("ARCHIVE_HARD_LINK")
            if member.ischr() or member.isblk():
                fail("ARCHIVE_DEVICE")
            if member.isfifo():
                fail("ARCHIVE_FIFO")
            if member.type == b"s":
                fail("ARCHIVE_SOCKET")
            if member.mode & ~0o777:
                fail("ARCHIVE_SPECIAL_MODE")
            expected = manifest.entries.get(relative)
            if expected is None:
                fail("ARCHIVE_UNTRACKED_ENTRY")
            if relative in actual:
                fail("ARCHIVE_DUPLICATE_NORMALIZED_PATH")
            if member.isdir():
                if expected.mode != "040000" or member.mode != 0o775 or member.size != 0:
                    fail("ARCHIVE_DIRECTORY_MODE_OR_TYPE")
                actual[relative] = expected
            elif member.isfile():
                if expected.mode not in ("100644", "100755"):
                    fail("ARCHIVE_FILE_TYPE")
                required_transport = 0o664 if expected.mode == "100644" else 0o775
                if member.mode != required_transport:
                    fail("ARCHIVE_FILE_MODE")
                if member.size != expected.size:
                    fail("ARCHIVE_FILE_SIZE")
                stream = handle.extractfile(member)
                if stream is None:
                    fail("ARCHIVE_FILE_READ")
                data = stream.read(expected.size + 1)
                if len(data) != expected.size:
                    fail("ARCHIVE_FILE_SIZE")
                total += len(data)
                if total > MAX_TOTAL_CONTENT_BYTES:
                    fail("ARCHIVE_TOTAL_SIZE")
                if data.startswith(b"version https://git-lfs.github.com/spec/v1"):
                    fail("ARCHIVE_GIT_LFS_POINTER")
                oid = git_oid("blob", data)
                if oid != expected.oid:
                    fail("ARCHIVE_BLOB_MISMATCH")
                actual[relative] = ManifestEntry(expected.mode, "blob", oid, len(data), relative, None)
                data_by_path[relative] = data
            elif member.issym():
                if expected.mode != "120000" or member.mode != 0o777:
                    fail("ARCHIVE_SYMLINK_TYPE_OR_MODE")
                if member.linkname != expected.target:
                    fail("ARCHIVE_SYMLINK_TARGET_MISMATCH")
                validate_symlink_target(relative, member.linkname, manifest.entries)
                raw = member.linkname.encode("utf-8")
                if git_oid("blob", raw) != expected.oid:
                    fail("ARCHIVE_SYMLINK_BLOB_MISMATCH")
                actual[relative] = expected
            else:
                fail("ARCHIVE_UNSUPPORTED_TYPE")
    missing = set(manifest.entries) - set(actual)
    if missing:
        fail("ARCHIVE_MISSING_ENTRY")
    for path, entry in manifest.entries.items():
        if entry.mode == "120000":
            resolve_symlink_chain(path, manifest.entries)
    root, trees = reconstruct_trees(actual)
    for path, entry in manifest.entries.items():
        if entry.mode == "040000" and trees.get(path) != entry.oid:
            fail("ARCHIVE_DIRECTORY_TREE_MISMATCH")
    if root != manifest.root_tree:
        fail("ARCHIVE_ROOT_TREE_MISMATCH")
    return actual, data_by_path, root


def validate_archive(archive, manifest):
    owns_pinned = not isinstance(archive, PinnedRegularFile)
    pinned = open_pinned_regular(archive, "ARCHIVE") if owns_pinned else archive
    try:
        result = validate_archive_stream(pinned.handle, manifest)
        pinned.verify_stable()
        return result
    finally:
        if owns_pinned:
            pinned.close()


def locate_archive(input_root, policy):
    root = require_absolute_canonical_directory(input_root, "INPUT_CACHE_ROOT")
    relative = policy["builder_archive_cache_relative_path"]
    if relative != ARCHIVE_RELATIVE:
        fail("ARCHIVE_RELATIVE_POLICY")
    archive = root.joinpath(*relative.split("/"))
    if archive.name != policy["source_archive_sha256"]:
        fail("ARCHIVE_CONTENT_ADDRESS_NAME")
    pinned = open_pinned_regular(archive, "ARCHIVE_OBJECT")
    try:
        if pinned.metadata.st_nlink != 1:
            fail("ARCHIVE_OBJECT_LINK_COUNT")
        if pinned.metadata.st_uid not in (0, os.getuid()):
            fail("ARCHIVE_OBJECT_OWNER")
        if stat.S_IMODE(pinned.metadata.st_mode) & 0o022:
            fail("ARCHIVE_OBJECT_PERMISSIONS_UNSAFE")
        if sha256_stream(pinned.handle) != policy["source_archive_sha256"]:
            fail("ARCHIVE_OBJECT_SHA256_MISMATCH")
        pinned.verify_stable()
        return pinned
    except Exception:
        pinned.close()
        raise


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def extract_validated(destination, manifest, data_by_path):
    destination = pathlib.Path(destination)
    parent = require_absolute_canonical_directory(destination.parent, "EXTRACTION_PARENT")
    if destination.exists() or destination.is_symlink():
        fail("EXTRACTION_DESTINATION_COLLISION")
    os.mkdir(destination, 0o700)
    try:
        for path, entry in sorted(manifest.entries.items(), key=lambda item: (item[0].count("/"), item[0].encode("utf-8"))):
            if entry.mode != "040000":
                continue
            target = destination.joinpath(*path.split("/"))
            os.mkdir(target, 0o700)
        for path, entry in sorted(manifest.entries.items(), key=lambda item: item[0].encode("utf-8")):
            target = destination.joinpath(*path.split("/"))
            if entry.mode in ("100644", "100755"):
                mode = 0o644 if entry.mode == "100644" else 0o755
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
                try:
                    data = data_by_path[path]
                    offset = 0
                    while offset < len(data):
                        offset += os.write(descriptor, data[offset:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                os.chmod(target, mode, follow_symlinks=False)
            elif entry.mode == "120000":
                os.symlink(entry.target, target)
        for path, entry in sorted(manifest.entries.items(), key=lambda item: (-item[0].count("/"), item[0].encode("utf-8"))):
            if entry.mode == "040000":
                target = destination.joinpath(*path.split("/"))
                os.chmod(target, 0o755)
                fsync_directory(target)
        fsync_directory(destination)
        fsync_directory(parent)
    except Exception:
        shutil.rmtree(destination)
        fsync_directory(parent)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--mode", choices=("verify-only", "extract"), required=True)
    parser.add_argument("--input-cache-root", required=True)
    parser.add_argument("--lock", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--destination")
    args = parser.parse_args(argv)
    if args.mode == "verify-only" and args.destination is not None:
        fail("DESTINATION_FORBIDDEN_IN_VERIFY_ONLY")
    if args.mode == "extract" and args.destination is None:
        fail("EXTRACTION_DESTINATION_REQUIRED")
    policy = parse_lock(args.lock)
    expected_manifest = pathlib.Path(args.lock).parent / pathlib.Path(policy["builder_tree_manifest_path"]).name
    if pathlib.Path(args.manifest) != expected_manifest:
        fail("BUILDER_MANIFEST_PATH_POLICY")
    manifest = parse_manifest(args.manifest, policy)
    archive = locate_archive(args.input_cache_root, policy)
    try:
        actual, data_by_path, root = validate_archive(archive, manifest)
        if args.mode == "extract":
            extract_validated(args.destination, manifest, data_by_path)
            archive.verify_stable()
    finally:
        archive.close()
    print("BUILDER_ARCHIVE_SHA256=" + ARCHIVE_SHA256)
    print("BUILDER_TREE=" + root)
    print("BUILDER_MANIFEST_SHA256=" + MANIFEST_SHA256)
    print("BUILDER_ENTRIES_VERIFIED=" + str(len(actual)))
    print("BUILDER_CODE_EXECUTED=NO")
    print("BUILDER_ARCHIVE_VALID=YES")


if __name__ == "__main__":
    try:
        main()
    except ValidationError as error:
        print("verify-builder-archive.py: " + str(error), file=sys.stderr)
        raise SystemExit(1)
