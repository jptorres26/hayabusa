"""The scanner options that change how records are built, not just which rules run."""

from __future__ import annotations

from hayabusa_py.engine.detect import Detector, RuleSet
from hayabusa_py.rules.config import RulesConfig
from hayabusa_py.rules.loader import LoadedRules

PWSH_400 = {
    "Event": {
        "System": {"Channel": "Windows PowerShell", "EventID": 400, "EventRecordID": 1},
        "EventData": {
            "Data": [
                "Available",
                "None",
                "NewEngineState=Available\n\tPreviousEngineState=None\n\n\tHostName=ConsoleHost\n\tHostVersion=2.0\n",
            ]
        },
    }
}


def _detector(config: RulesConfig, **kwargs) -> Detector:
    empty = RuleSet(rules=[], loaded=LoadedRules())
    return Detector(empty, config, **kwargs)


def test_the_scan_passes_the_flag_down_to_every_record(monkeypatch) -> None:
    """A flag the CLI accepts but the scan ignores is worse than no flag at all."""
    import hayabusa_py.engine.detect as detect

    seen: list[bool] = []
    original = detect.create_lazy_rec_info

    def spy(data, path, alias, **kwargs):
        seen.append(kwargs.get("no_pwsh_field_extraction", False))
        return original(data, path, alias, **kwargs)

    monkeypatch.setattr(detect, "create_lazy_rec_info", spy)
    config = RulesConfig()
    list(_detector(config).scan_records("pwsh.evtx", [PWSH_400]))
    list(_detector(config, no_pwsh_field_extraction=True).scan_records("pwsh.evtx", [PWSH_400]))
    assert seen == [False, True]


def test_the_flag_reaches_the_record_builder() -> None:
    """``--no-pwsh-field-extraction`` has to change what the record looks like, not just parse."""
    from hayabusa_py.evtx.record import create_lazy_rec_info

    config = RulesConfig()
    with_fields = create_lazy_rec_info(PWSH_400, "pwsh.evtx", config.eventkey_alias)
    without = create_lazy_rec_info(
        PWSH_400, "pwsh.evtx", config.eventkey_alias, no_pwsh_field_extraction=True
    )
    assert with_fields.key_to_value, "the classic PowerShell blob should be split into fields"
    assert with_fields.key_to_value.get("HostName") == "ConsoleHost"
    assert without.key_to_value == {}

    assert _detector(config, no_pwsh_field_extraction=True).no_pwsh_field_extraction is True
    assert _detector(config).no_pwsh_field_extraction is False
