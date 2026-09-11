"""Tests for ``service.uploads`` -- the part of the service that handles hostile input."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from service.config import ServiceConfig
from service.uploads import (
    EVTX_MAGIC,
    UploadRejected,
    extract_evtx,
    inspect_archive,
    looks_like_evtx,
    prepare_inputs,
    safe_display_name,
    store_stream,
)


def evtx_bytes(size: int = 512) -> bytes:
    return EVTX_MAGIC + b"\x00" * max(0, size - len(EVTX_MAGIC))


def make_zip(path: Path, entries: dict[str, bytes], *, compress: bool = True) -> Path:
    mode = zipfile.ZIP_DEFLATED if compress else zipfile.ZIP_STORED
    with zipfile.ZipFile(path, "w", mode) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


# -- storing ---------------------------------------------------------------------------------


def test_store_stream_records_size_and_digest(tmp_path: Path) -> None:
    stored = store_stream([b"abc", b"def"], tmp_path / "u.bin", max_bytes=100, filename="Security.evtx")
    assert stored.size_bytes == 6
    assert stored.sha256 == "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721"
    assert stored.display_name == "Security.evtx"
    assert stored.path.read_bytes() == b"abcdef"


def test_store_stream_refuses_an_oversized_upload_without_keeping_it(tmp_path: Path) -> None:
    target = tmp_path / "u.bin"
    with pytest.raises(UploadRejected, match="larger than"):
        store_stream([b"x" * 600, b"x" * 600], target, max_bytes=1000)
    assert not target.exists()


def test_store_stream_refuses_an_empty_upload(tmp_path: Path) -> None:
    with pytest.raises(UploadRejected, match="empty"):
        store_stream([b""], tmp_path / "u.bin", max_bytes=10)


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("Security.evtx", "Security.evtx"),
        ("../../etc/passwd", "passwd"),
        (r"C:\Windows\System32\config\SAM", "SAM"),
        ("../../../", "upload"),
        ("", "upload"),
        ("odd name; rm -rf.evtx", "odd_name_rm_-rf.evtx"),
    ],
)
def test_safe_display_name(given: str, expected: str) -> None:
    assert safe_display_name(given) == expected


# -- archives --------------------------------------------------------------------------------


def test_extracts_evtx_members(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "logs.zip", {"Security.evtx": evtx_bytes(), "sub/System.evtx": evtx_bytes()})
    out = extract_evtx(archive, tmp_path / "work", max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)
    assert sorted(p.name for p in out.files) == ["Security.evtx", "System.evtx"]
    assert all(looks_like_evtx(p) for p in out.files)


def test_path_traversal_entries_cannot_escape(tmp_path: Path) -> None:
    work = tmp_path / "work"
    archive = make_zip(
        tmp_path / "evil.zip",
        {
            "../../escaped.evtx": evtx_bytes(),
            r"..\..\windows\system32\evil.evtx": evtx_bytes(),
            "/absolute.evtx": evtx_bytes(),
        },
    )
    out = extract_evtx(archive, work, max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)
    # every entry is flattened into the work directory, and nothing lands outside it
    assert out.files
    for path in out.files:
        assert path.parent.resolve() == work.resolve()
    assert not (tmp_path / "escaped.evtx").exists()
    assert not (tmp_path.parent / "escaped.evtx").exists()


def test_same_named_entries_do_not_overwrite_each_other(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "dup.zip", {"a/Security.evtx": evtx_bytes(600), "b/Security.evtx": evtx_bytes(700)})
    out = extract_evtx(archive, tmp_path / "work", max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)
    assert len(out.files) == 2
    assert len({p.name for p in out.files}) == 2


def test_non_evtx_members_are_skipped(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "mixed.zip", {"Security.evtx": evtx_bytes(), "notes.txt": b"hello", "fake.evtx": b"not an evtx"})
    out = extract_evtx(archive, tmp_path / "work", max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)
    assert [p.name for p in out.files] == ["Security.evtx"]
    assert any("notes.txt" in s for s in out.skipped)
    assert any("fake.evtx" in s for s in out.skipped)


def test_an_archive_of_nothing_usable_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "empty.zip", {"notes.txt": b"hello"})
    with pytest.raises(UploadRejected, match="no readable .evtx"):
        extract_evtx(archive, tmp_path / "work", max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)


def test_too_many_members_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "many.zip", {f"f{n}.evtx": evtx_bytes(64) for n in range(20)})
    with pytest.raises(UploadRejected, match="more than the 5 allowed"):
        inspect_archive(archive, max_members=5, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)


def test_an_oversized_member_is_rejected(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "big.zip", {"Security.evtx": evtx_bytes(50_000)})
    with pytest.raises(UploadRejected, match="more than the .* allowed for one file"):
        inspect_archive(archive, max_members=10, max_member_bytes=1024, max_total_bytes=10 * 1024**2, max_expansion_ratio=10_000)


def test_a_decompression_bomb_is_rejected(tmp_path: Path) -> None:
    # highly compressible: 8 MB of zeros shrinks to a few KB
    archive = make_zip(tmp_path / "bomb.zip", {"Security.evtx": EVTX_MAGIC + b"\x00" * (8 * 1024**2)})
    with pytest.raises(UploadRejected, match="decompression bomb"):
        inspect_archive(archive, max_members=10, max_member_bytes=64 * 1024**2, max_total_bytes=64 * 1024**2, max_expansion_ratio=50)


def test_a_header_that_disagrees_with_the_data_is_rejected_cleanly(tmp_path: Path, monkeypatch) -> None:
    """A doctored header must produce a message for the technician, not a server error."""
    archive = make_zip(tmp_path / "liar.zip", {"Security.evtx": evtx_bytes(4096)}, compress=False)
    real_infolist = zipfile.ZipFile.infolist

    def understate(self):  # noqa: ANN001
        entries = real_infolist(self)
        for entry in entries:
            entry.file_size = 10  # claim 10 bytes, actually 4096
        return entries

    monkeypatch.setattr(zipfile.ZipFile, "infolist", understate)
    with pytest.raises(UploadRejected, match="could not be extracted"):
        extract_evtx(archive, tmp_path / "work", max_members=10, max_member_bytes=100, max_total_bytes=100, max_expansion_ratio=10_000)


def test_a_corrupt_archive_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
    with pytest.raises(UploadRejected, match="could not be read"):
        inspect_archive(path, max_members=10, max_member_bytes=10_000, max_total_bytes=100_000, max_expansion_ratio=1000)


# -- dispatch --------------------------------------------------------------------------------


def test_prepare_inputs_accepts_a_bare_evtx(tmp_path: Path) -> None:
    stored = store_stream([evtx_bytes()], tmp_path / "u.bin", max_bytes=10_000, filename="Security.evtx")
    files, skipped = prepare_inputs(stored, tmp_path / "work", ServiceConfig())
    assert files == [stored.path] and skipped == []


def test_prepare_inputs_accepts_a_zip(tmp_path: Path) -> None:
    archive = make_zip(tmp_path / "logs.zip", {"Security.evtx": evtx_bytes()})
    stored = store_stream([archive.read_bytes()], tmp_path / "u.bin", max_bytes=10_000, filename="logs.zip")
    files, _ = prepare_inputs(stored, tmp_path / "work", ServiceConfig())
    assert [p.name for p in files] == ["Security.evtx"]


def test_prepare_inputs_rejects_anything_else(tmp_path: Path) -> None:
    stored = store_stream([b"just some text"], tmp_path / "u.bin", max_bytes=10_000, filename="notes.txt")
    with pytest.raises(UploadRejected, match="neither an .evtx file nor a .zip"):
        prepare_inputs(stored, tmp_path / "work", ServiceConfig())


def test_a_zip_inside_the_upload_is_not_recursed(tmp_path: Path) -> None:
    """Nested archives are not unpacked: one level is all the service promises."""
    inner = make_zip(tmp_path / "inner.zip", {"Security.evtx": evtx_bytes()})
    outer = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    stored = store_stream([outer.read_bytes()], tmp_path / "u.bin", max_bytes=100_000, filename="outer.zip")
    with pytest.raises(UploadRejected, match="no readable .evtx"):
        prepare_inputs(stored, tmp_path / "work", ServiceConfig())


def test_store_stream_from_a_file_handle(tmp_path: Path) -> None:
    source = io.BytesIO(evtx_bytes(2048))
    from service.uploads import iter_file_chunks

    stored = store_stream(iter_file_chunks(source), tmp_path / "u.bin", max_bytes=10_000)
    assert stored.size_bytes == 2048
