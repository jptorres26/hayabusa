"""Tests for ``hayabusa_py.evtx.wevtapi_reader``.

The Windows Event Log API is not available here, so a stub stands in for ``win32evtlog``: it
exercises the batching, handle-closing and error handling, and feeds real event XML through the
real converter. The Windows-only part left untested is the API call itself, which the
``windows-latest`` CI job covers.
"""

from __future__ import annotations

import pytest

from hayabusa_py.evtx import wevtapi_reader as reader

EVENT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>\
<Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385f-c22a-43e0-bf4c-06f5698ffbd9}}"></Provider>\
<EventID>1</EventID><TimeCreated SystemTime="2021-02-01T11:13:11.1959551Z"></TimeCreated>\
<EventRecordID>{rid}</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel>\
<Computer>fs02.offsec.lan</Computer></System>\
<EventData><Data Name="Image">C:\\Windows\\System32\\setspn.exe</Data></EventData></Event>"""


class _Handle:
    def __init__(self, payload: object = None) -> None:
        self.payload = payload
        self.closed = False

    def Close(self) -> None:  # noqa: N802 - the pywin32 method name
        self.closed = True


class StubApi:
    """Enough of ``win32evtlog`` to drive :func:`iter_evtx_records`."""

    def __init__(self, xmls: list[str], *, fail_render: set[int] | None = None) -> None:
        self.xmls = xmls
        self.fail_render = fail_render or set()
        self.handles: list[_Handle] = []
        self.calls: list[tuple] = []
        self.position = 0

    def EvtQuery(self, path, flags, query, session):  # noqa: N802, ANN001
        self.calls.append(("EvtQuery", path, flags, query, session))
        handle = _Handle()
        self.handles.append(handle)
        return handle

    def EvtNext(self, result_set, count, timeout, flags):  # noqa: N802, ANN001
        self.calls.append(("EvtNext", count, timeout, flags))
        batch = []
        for index in range(self.position, min(self.position + count, len(self.xmls))):
            handle = _Handle(index)
            self.handles.append(handle)
            batch.append(handle)
        self.position += len(batch)
        return tuple(batch)

    def EvtRender(self, event, flags):  # noqa: N802, ANN001
        if event.payload in self.fail_render:
            raise OSError(13, "The data is invalid")
        return self.xmls[event.payload]

    def EvtOpenLog(self, path, flags, session=None):  # noqa: N802, ANN001
        handle = _Handle()
        self.handles.append(handle)
        return handle

    def EvtGetLogInfo(self, log, property_id):  # noqa: N802, ANN001
        return (len(self.xmls), 4)


@pytest.fixture
def evtx_file(tmp_path):
    path = tmp_path / "Security.evtx"
    path.write_bytes(reader.EVTX_MAGIC + b"\x00" * 120)
    return path


@pytest.fixture
def stub(monkeypatch):
    def install(xmls, **kwargs):
        api = StubApi(xmls, **kwargs)
        monkeypatch.setattr(reader, "_API", api)
        return api

    monkeypatch.setattr(reader, "_API", None)
    return install


def test_reads_every_record_in_order(evtx_file, stub) -> None:
    api = stub([EVENT_XML.format(rid=n) for n in range(1, 1200)])
    records = list(reader.iter_evtx_records(evtx_file))
    assert len(records) == 1199
    assert [r["Event"]["System"]["EventRecordID"] for r in records] == list(range(1, 1200))
    assert records[0]["Event"]["EventData"] == {"Image": "C:\\Windows\\System32\\setspn.exe"}
    # batched, not one call per record: three full-ish batches plus the empty one that ends it
    assert sum(1 for call in api.calls if call[0] == "EvtNext") == 4


def test_values_are_normalized_for_the_windows_renderer(evtx_file, stub) -> None:
    stub([EVENT_XML.format(rid=1)])
    system = next(reader.iter_evtx_records(evtx_file))["Event"]["System"]
    assert system["Provider_attributes"]["Guid"] == "5770385F-C22A-43E0-BF4C-06F5698FFBD9"
    assert system["TimeCreated_attributes"]["SystemTime"] == "2021-02-01T11:13:11.195955Z"


def test_every_handle_is_closed(evtx_file, stub) -> None:
    api = stub([EVENT_XML.format(rid=n) for n in range(3)])
    list(reader.iter_evtx_records(evtx_file))
    assert api.handles and all(handle.closed for handle in api.handles)


def test_a_bad_record_is_counted_and_skipped(evtx_file, stub) -> None:
    stub([EVENT_XML.format(rid=n) for n in range(5)], fail_render={2})
    stats = reader.ReadStats()
    errors: list[str] = []
    records = list(reader.iter_evtx_records(evtx_file, stats=stats, on_error=errors.append))
    assert len(records) == 4
    assert stats.records == 4
    assert stats.render_errors == 1
    assert len(errors) == 1 and "could not be rendered" in errors[0]
    assert stats.first_error == errors[0]


def test_query_is_passed_through(evtx_file, stub) -> None:
    api = stub([EVENT_XML.format(rid=1)])
    query = reader.record_id_query(100, 200)
    list(reader.iter_evtx_records(evtx_file, query=query))
    call = next(c for c in api.calls if c[0] == "EvtQuery")
    assert call[3] == query
    assert call[2] == (
        reader.EVT_QUERY_FILE_PATH
        | reader.EVT_QUERY_FORWARD_DIRECTION
        | reader.EVT_QUERY_TOLERATE_QUERY_ERRORS
    )


def test_no_more_items_ends_the_iteration(evtx_file, stub, monkeypatch) -> None:
    api = stub([EVENT_XML.format(rid=1)])
    original = api.EvtNext

    def fail_after_first(*args, **kwargs):
        if api.position:
            raise OSError(reader.ERROR_NO_MORE_ITEMS, "No more data is available")
        return original(*args, **kwargs)

    monkeypatch.setattr(api, "EvtNext", fail_after_first)
    assert len(list(reader.iter_evtx_records(evtx_file))) == 1


def test_open_failure_becomes_a_read_error(evtx_file, stub, monkeypatch) -> None:
    api = stub([])

    def refuse(*args, **kwargs):
        error = OSError(5, "Access is denied.")
        error.winerror = 5
        raise error

    monkeypatch.setattr(api, "EvtQuery", refuse)
    with pytest.raises(reader.EvtxReadError) as info:
        list(reader.iter_evtx_records(evtx_file))
    assert info.value.winerror == 5
    assert "needs read access" in str(info.value)


def test_a_non_evtx_file_is_rejected_before_the_api(tmp_path, stub) -> None:
    api = stub([])
    path = tmp_path / "notes.txt"
    path.write_bytes(b"just some text")
    with pytest.raises(reader.EvtxReadError, match="not an EVTX file"):
        list(reader.iter_evtx_records(path))
    assert api.calls == []


def test_a_missing_file_is_rejected(tmp_path, stub) -> None:
    stub([])
    with pytest.raises(reader.EvtxReadError, match="cannot be opened"):
        list(reader.iter_evtx_records(tmp_path / "absent.evtx"))


def test_record_count_uses_the_log_info_property(evtx_file, stub) -> None:
    stub([EVENT_XML.format(rid=n) for n in range(7)])
    assert reader.record_count(evtx_file) == 7


@pytest.mark.parametrize(
    ("start", "stop", "expected"),
    [
        (None, None, "*"),
        (100, None, "*[System[EventRecordID >= 100]]"),
        (None, 200, "*[System[EventRecordID < 200]]"),
        (100, 200, "*[System[EventRecordID >= 100 and EventRecordID < 200]]"),
    ],
)
def test_record_id_query(start, stop, expected) -> None:
    assert reader.record_id_query(start, stop) == expected
