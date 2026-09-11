"""Accepting a file from a technician: size limits, type checks and safe archive extraction.

This is the part of the service that touches attacker-shaped input, so it is deliberately
conservative:

* the upload is streamed to disk against a byte budget -- it is never held in memory, and the
  connection is cut as soon as it exceeds the cap, so a huge POST cannot fill the disk;
* a ``.zip`` is inspected before anything is written: entry count, per-entry size, total
  uncompressed size and the compression ratio (the zip-bomb guard), and every entry name is
  resolved against the destination so ``..\\..\\windows\\system32`` and absolute paths are
  refused rather than sanitized into something that might still escape;
* only regular files survive extraction (no symlinks, no directories with surprising modes), and
  only entries that actually start with the EVTX signature are kept.

Nothing here trusts the client-supplied filename: it is recorded for display and never used as a
path.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from collections.abc import AsyncIterable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath, PureWindowsPath

EVTX_MAGIC = b"ElfFile\x00"
ZIP_MAGIC = b"PK\x03\x04"
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UploadRejected(Exception):
    """The upload cannot be accepted. The message is shown to the technician verbatim."""


@dataclass(slots=True)
class StoredUpload:
    path: Path
    size_bytes: int
    sha256: str
    display_name: str


@dataclass(slots=True)
class ExtractResult:
    files: list[Path] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def safe_display_name(filename: str) -> str:
    """A filename safe to store and show: no directories, no surprises, never empty."""
    name = PureWindowsPath(PurePosixPath(filename or "").name).name
    name = _SAFE_NAME_RE.sub("_", name).strip("._") or "upload"
    return name[:120]


class _Sink:
    """Writes an upload to disk while hashing it and holding it to a byte budget."""

    __slots__ = ("digest", "handle", "max_bytes", "total")

    def __init__(self, destination: Path, max_bytes: int) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.handle = open(destination, "wb")  # noqa: SIM115 - closed by the caller
        self.max_bytes = max_bytes
        self.digest = hashlib.sha256()
        self.total = 0

    def write(self, chunk: bytes) -> None:
        if not chunk:
            return
        self.total += len(chunk)
        if self.total > self.max_bytes:
            raise UploadRejected(f"the upload is larger than the {self.max_bytes // 1024**2} MB limit")
        self.digest.update(chunk)
        self.handle.write(chunk)

    def close(self) -> None:
        self.handle.close()


def _finish(sink: _Sink, destination: Path, filename: str) -> StoredUpload:
    if sink.total == 0:
        destination.unlink(missing_ok=True)
        raise UploadRejected("the upload was empty")
    return StoredUpload(destination, sink.total, sink.digest.hexdigest(), safe_display_name(filename))


def store_stream(chunks: Iterable[bytes], destination: Path, *, max_bytes: int, filename: str = "") -> StoredUpload:
    """Write an upload to ``destination``, refusing it the moment it exceeds ``max_bytes``."""
    sink = _Sink(destination, max_bytes)
    try:
        for chunk in chunks:
            sink.write(chunk)
    except UploadRejected:
        sink.close()
        destination.unlink(missing_ok=True)
        raise
    finally:
        sink.close()
    return _finish(sink, destination, filename)


async def store_async_stream(chunks: AsyncIterable[bytes], destination: Path, *, max_bytes: int, filename: str = "") -> StoredUpload:
    """The same, for the web app: an ``UploadFile`` yields its chunks asynchronously.

    The upload is never held in memory and never fully written before the limit is enforced, so
    a client that keeps sending is cut off at the cap rather than after it has filled the disk.
    """
    sink = _Sink(destination, max_bytes)
    try:
        async for chunk in chunks:
            sink.write(chunk)
    except UploadRejected:
        sink.close()
        destination.unlink(missing_ok=True)
        raise
    finally:
        sink.close()
    return _finish(sink, destination, filename)


def looks_like_evtx(path: Path) -> bool:
    with open(path, "rb") as handle:
        return handle.read(8) == EVTX_MAGIC


def looks_like_zip(path: Path) -> bool:
    with open(path, "rb") as handle:
        return handle.read(4) == ZIP_MAGIC


def _entry_destination(root: Path, name: str) -> Path | None:
    """Where an archive entry may be written, or None when the name is not acceptable.

    Zip entry names are attacker-controlled: they can be absolute, contain ``..``, use backslash
    separators, or name a Windows drive or UNC path. Rather than rewriting such a name into
    something plausible, this flattens the entry to its base name under ``root`` and verifies the
    result really is inside ``root``.
    """
    if not name or name.endswith(("/", "\\")):
        return None
    base = PureWindowsPath(PurePosixPath(name.replace("\\", "/")).name).name
    if not base or base in (".", ".."):
        return None
    candidate = (root / safe_display_name(base)).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        return None
    return candidate


def _unique(path: Path) -> Path:
    """A path that does not exist yet, so two archive entries cannot overwrite each other."""
    if not path.exists():
        return path
    stem, suffix = path.stem, path.suffix
    for index in range(1, 10_000):
        candidate = path.with_name(f"{stem}_{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise UploadRejected("the archive contains too many files with the same name")


def inspect_archive(
    archive: Path,
    *,
    max_members: int,
    max_member_bytes: int,
    max_total_bytes: int,
    max_expansion_ratio: int,
) -> list[zipfile.ZipInfo]:
    """Check an archive's declared contents before extracting a single byte of it."""
    try:
        with zipfile.ZipFile(archive) as zf:
            entries = zf.infolist()
    except zipfile.BadZipFile as exc:
        raise UploadRejected(f"the archive could not be read ({exc})") from exc
    members = [entry for entry in entries if not entry.is_dir()]
    if not members:
        raise UploadRejected("the archive is empty")
    if len(members) > max_members:
        raise UploadRejected(f"the archive holds {len(members)} files, more than the {max_members} allowed")
    declared = 0
    compressed = 0
    for entry in members:
        if entry.file_size > max_member_bytes:
            raise UploadRejected(
                f"'{entry.filename}' expands to {entry.file_size // 1024**2} MB, "
                f"more than the {max_member_bytes // 1024**2} MB allowed for one file"
            )
        declared += entry.file_size
        compressed += entry.compress_size
    if declared > max_total_bytes:
        raise UploadRejected(
            f"the archive expands to {declared // 1024**2} MB, more than the {max_total_bytes // 1024**2} MB allowed"
        )
    if compressed > 0 and declared // max(compressed, 1) > max_expansion_ratio:
        raise UploadRejected(
            f"the archive expands {declared // max(compressed, 1)}x, which looks like a decompression bomb"
        )
    return members


def extract_evtx(
    archive: Path,
    destination: Path,
    *,
    max_members: int,
    max_member_bytes: int,
    max_total_bytes: int,
    max_expansion_ratio: int,
) -> ExtractResult:
    """Extract the ``.evtx`` members of ``archive`` into ``destination``.

    The declared sizes are checked first, then enforced again while writing: a zip header can
    lie, so each member is copied against its own byte budget rather than trusted.
    """
    members = inspect_archive(
        archive,
        max_members=max_members,
        max_member_bytes=max_member_bytes,
        max_total_bytes=max_total_bytes,
        max_expansion_ratio=max_expansion_ratio,
    )
    destination.mkdir(parents=True, exist_ok=True)
    result = ExtractResult()
    written = 0
    with zipfile.ZipFile(archive) as zf:
        for entry in members:
            target = _entry_destination(destination, entry.filename)
            if target is None:
                result.skipped.append(f"{entry.filename} (unsafe name)")
                continue
            if not target.name.lower().endswith(".evtx"):
                result.skipped.append(f"{entry.filename} (not a .evtx file)")
                continue
            target = _unique(target)
            budget = min(max_member_bytes, max_total_bytes - written)
            try:
                copied = _copy_member(zf, entry, target, budget)
            except UploadRejected:
                target.unlink(missing_ok=True)
                raise
            written += copied
            if copied < len(EVTX_MAGIC) or not looks_like_evtx(target):
                target.unlink(missing_ok=True)
                result.skipped.append(f"{entry.filename} (not an EVTX file)")
                continue
            result.files.append(target)
    if not result.files:
        detail = "; ".join(result.skipped[:5])
        raise UploadRejected(f"the archive held no readable .evtx files ({detail})" if detail else "the archive held no .evtx files")
    return result


def _copy_member(zf: zipfile.ZipFile, entry: zipfile.ZipInfo, target: Path, budget: int) -> int:
    """Copy one member, enforcing ``budget`` while writing rather than trusting the header.

    Python's ``zipfile`` stops at the declared size and verifies the CRC, so a member whose
    header disagrees with its data surfaces as ``BadZipFile``; that is a broken (or doctored)
    archive, and it is reported as such instead of escaping as a server error.
    """
    copied = 0
    try:
        with zf.open(entry) as source, open(target, "wb") as handle:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > budget:
                    # Defence in depth: CPython's zipfile already stops at the declared size, so
                    # reaching this would mean the reader itself over-produced.
                    raise UploadRejected(
                        f"'{entry.filename}' holds more data than its archive entry declared, "
                        "which is how a decompression bomb is built"
                    )
                handle.write(chunk)
    except (zipfile.BadZipFile, OSError, EOFError) as exc:
        raise UploadRejected(f"'{entry.filename}' could not be extracted ({exc})") from exc
    return copied


def prepare_inputs(stored: StoredUpload, work_dir: Path, config) -> tuple[list[Path], list[str]]:  # noqa: ANN001
    """Turn a stored upload into the list of ``.evtx`` files to scan.

    Accepts a single ``.evtx`` or a ``.zip`` of them; anything else is rejected with a message
    that says what the technician should send instead.
    """
    if looks_like_evtx(stored.path):
        return [stored.path], []
    if looks_like_zip(stored.path):
        extracted = extract_evtx(
            stored.path,
            work_dir,
            max_members=config.max_members,
            max_member_bytes=config.max_member_bytes,
            max_total_bytes=config.max_total_bytes,
            max_expansion_ratio=config.max_expansion_ratio,
        )
        return extracted.files, extracted.skipped
    raise UploadRejected(
        "this is neither an .evtx file nor a .zip of them - export the logs with "
        "`wevtutil epl <channel> <file>.evtx` or with client/Export-WinEvtx.ps1"
    )


def iter_file_chunks(handle, chunk_size: int = 1024 * 1024) -> Iterator[bytes]:  # noqa: ANN001
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            return
        yield chunk
