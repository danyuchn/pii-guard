"""Tests for the ``pii-guard-hookd terms`` commands.

The recurring assertion here is negative: whatever these commands print, it is
never a value out of the customer table.  Terminal output ends up in scrollback
and often in a transcript, so a leak here would undo the whole feature.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pii_guard.hookd.__main__ import main
from pii_guard.hookd.state import HookdConfig

NAMES = ("吳孟儒", "蔡佩君", "鄭宇翔")
MOBILES = ("0912000111", "0912000222", "0912000333")
ORDERS = ("ORD-000101", "ORD-000102", "ORD-000103")
SECRETS = (*NAMES, *MOBILES, *ORDERS)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Keep every run away from the developer's own hookd installation."""

    monkeypatch.setenv("PII_GUARD_HOOKD_HOME", str(tmp_path / "hookd"))
    monkeypatch.setenv("PII_GUARD_HOOKD_CONFIG", str(tmp_path / "config" / "hookd.json"))
    monkeypatch.setattr(HookdConfig, "from_env", classmethod(
        lambda cls: cls(home=tmp_path / "hookd")
    ))
    return tmp_path


def registered(tmp_path: Path) -> list[str]:
    """The description files the installer config currently names."""

    config = tmp_path / "config" / "hookd.json"
    if not config.is_file():
        return []
    payload = json.loads(config.read_text(encoding="utf-8"))
    return list(payload.get("policy", {}).get("reference_sources", []))


@pytest.fixture()
def table(tmp_path: Path) -> Path:
    rows = "\n".join(
        f"{name},{mobile},{order},{9000 + index}"
        for index, (name, mobile, order) in enumerate(zip(NAMES, MOBILES, ORDERS, strict=True))
    )
    target = tmp_path / "customers.csv"
    target.write_text("姓名,手機,訂單編號,金額\n" + rows + "\n", encoding="utf-8")
    return target


@pytest.fixture()
def project(tmp_path: Path) -> Path:
    target = tmp_path / "project"
    target.mkdir()
    return target


def assert_no_values(text: str) -> None:
    for value in SECRETS:
        assert value not in text, f"{value} leaked into the output"


def test_inspect_prints_columns_and_types(table: Path, capsys) -> None:
    assert main(["terms", "inspect", str(table)]) == 0

    out = capsys.readouterr().out
    assert "姓名" in out
    assert "訂單／案件編號" in out
    assert "不要遮" in out


def test_inspect_prints_no_values(table: Path, capsys) -> None:
    main(["terms", "inspect", str(table)])

    assert_no_values(capsys.readouterr().out)


def test_inspect_json_is_machine_readable_and_valueless(table: Path, capsys) -> None:
    assert main(["terms", "inspect", str(table), "--json"]) == 0

    out = capsys.readouterr().out
    payload = json.loads(out)
    assert [column["name"] for column in payload["columns"]] == [
        "姓名",
        "手機",
        "訂單編號",
        "金額",
    ]
    assert payload["columns"][0]["guessed_type"] == "PERSON"
    assert_no_values(out)


def test_import_with_yes_records_every_guess(table: Path, project: Path, capsys) -> None:
    assert main(["terms", "import", str(table), "--yes", "--project", str(project)]) == 0

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    columns = stored["sources"][0]["columns"]
    assert columns["姓名"] == "PERSON"
    assert columns["手機"] == "TW_MOBILE"
    assert "金額" not in columns
    assert_no_values(capsys.readouterr().out)


def test_import_with_a_map_overrides_the_guesses(table: Path, project: Path, capsys) -> None:
    exit_code = main(
        [
            "terms",
            "import",
            str(table),
            "--map",
            "姓名=PERSON,手機=SKIP,訂單編號=CUSTOM",
            "--project",
            str(project),
        ]
    )

    assert exit_code == 0
    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    columns = stored["sources"][0]["columns"]
    assert columns == {"姓名": "PERSON", "訂單編號": "CUSTOM"}
    assert_no_values(capsys.readouterr().out)


def test_import_reports_counts_only(table: Path, project: Path, capsys) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    out = capsys.readouterr().out
    assert "將自動遮蔽：" in out
    assert "姓名 3 筆" in out
    assert_no_values(out)


def test_import_records_a_shape_rule_for_order_numbers(
    table: Path, project: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    patterns = stored["sources"][0]["patterns"]
    assert [entry["type"] for entry in patterns] == ["ORDER_ID"]
    capsys.readouterr()


def test_import_does_not_add_a_shape_rule_for_a_covered_type(
    table: Path, project: Path, capsys
) -> None:
    # Mobiles already have a recognizer, so a second pattern would be noise.
    main(
        [
            "terms",
            "import",
            str(table),
            "--map",
            "手機=TW_MOBILE",
            "--project",
            str(project),
        ]
    )

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    assert stored["sources"][0]["patterns"] == []
    capsys.readouterr()


def test_import_without_materialize_writes_no_values_to_disk(
    table: Path, project: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    capsys.readouterr()
    assert not (project / ".pii-guard" / "terms.txt").exists()
    written = (project / ".pii-guard" / "sources.json").read_text(encoding="utf-8")
    assert_no_values(written)


def test_materialize_writes_the_term_file_on_request(
    table: Path, project: Path, capsys
) -> None:
    main(
        [
            "terms",
            "import",
            str(table),
            "--yes",
            "--materialize",
            "--project",
            str(project),
        ]
    )

    terms = project / ".pii-guard" / "terms.txt"
    assert "PERSON\t吳孟儒" in terms.read_text(encoding="utf-8")
    assert_no_values(capsys.readouterr().out)


def test_importing_the_same_table_twice_keeps_one_entry(
    table: Path, project: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    main(["terms", "import", str(table), "--map", "姓名=PERSON", "--project", str(project)])

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    assert len(stored["sources"]) == 1
    assert stored["sources"][0]["columns"] == {"姓名": "PERSON"}
    capsys.readouterr()


def test_import_answers_the_interactive_prompts(
    table: Path, project: Path, capsys, monkeypatch
) -> None:
    # Accept, accept, skip, accept.
    answers = iter(["", "", "s", ""])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))

    assert main(["terms", "import", str(table), "--project", str(project)]) == 0

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    assert "訂單編號" not in stored["sources"][0]["columns"]
    assert stored["sources"][0]["columns"]["姓名"] == "PERSON"
    assert_no_values(capsys.readouterr().out)


def test_an_invalid_map_is_refused(table: Path, project: Path, capsys) -> None:
    exit_code = main(
        ["terms", "import", str(table), "--map", "姓名", "--project", str(project)]
    )

    assert exit_code == 1
    assert "INVALID_MAP" in capsys.readouterr().err
    assert not (project / ".pii-guard" / "sources.json").exists()


def test_status_lists_the_sources_and_counts(table: Path, project: Path, capsys) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    assert main(["terms", "status", "--project", str(project)]) == 0

    out = capsys.readouterr().out
    assert str(table) in out
    assert "姓名 3 筆" in out
    assert "保護服務" in out
    assert_no_values(out)


def test_status_on_an_empty_project_says_so(project: Path, capsys) -> None:
    assert main(["terms", "status", "--project", str(project)]) == 0

    assert "尚未匯入任何名單" in capsys.readouterr().out


def test_remove_drops_one_source(table: Path, project: Path, capsys) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    assert main(["terms", "remove", str(table), "--project", str(project)]) == 0

    stored = json.loads((project / ".pii-guard" / "sources.json").read_text(encoding="utf-8"))
    assert stored["sources"] == []
    capsys.readouterr()


def test_remove_all_clears_every_source(table: Path, project: Path, capsys) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    assert main(["terms", "remove", "--all", "--project", str(project)]) == 0

    assert json.loads(
        (project / ".pii-guard" / "sources.json").read_text(encoding="utf-8")
    )["sources"] == []
    capsys.readouterr()


def test_remove_needs_a_target(project: Path, capsys) -> None:
    assert main(["terms", "remove", "--project", str(project)]) == 1

    assert "--all" in capsys.readouterr().err


def test_import_adds_the_guard_directory_to_gitignore(
    table: Path, project: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    assert ".pii-guard/" in (project / ".gitignore").read_text(encoding="utf-8")


def test_import_registers_the_project_with_the_service(
    table: Path, project: Path, tmp_path: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    assert registered(tmp_path) == [str(project / ".pii-guard" / "sources.json")]
    assert "已把這個專案登記給保護服務" in capsys.readouterr().out


def test_importing_twice_registers_the_project_once(
    table: Path, project: Path, tmp_path: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    assert len(registered(tmp_path)) == 1


def test_registration_keeps_an_allowlist_the_user_edited_by_hand(
    table: Path, project: Path, tmp_path: Path, capsys
) -> None:
    config = tmp_path / "config" / "hookd.json"
    config.parent.mkdir(parents=True)
    config.write_text(
        json.dumps(
            {
                "repo": "/somewhere",
                "serve_command": ["uv", "run", "pii-guard-hookd", "serve"],
                "policy": {"allowed_tools": ["mcp__local-db__query"]},
            }
        ),
        encoding="utf-8",
    )

    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    payload = json.loads(config.read_text(encoding="utf-8"))
    assert payload["policy"]["allowed_tools"] == ["mcp__local-db__query"]
    assert payload["serve_command"] == ["uv", "run", "pii-guard-hookd", "serve"]
    assert len(payload["policy"]["reference_sources"]) == 1


def test_remove_all_deregisters_the_project(
    table: Path, project: Path, tmp_path: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    main(["terms", "remove", "--all", "--project", str(project)])

    assert registered(tmp_path) == []
    assert "撤掉" in capsys.readouterr().out


def test_removing_the_last_source_deregisters_the_project(
    table: Path, project: Path, tmp_path: Path, capsys
) -> None:
    main(["terms", "import", str(table), "--yes", "--project", str(project)])
    capsys.readouterr()

    main(["terms", "remove", str(table), "--project", str(project)])
    capsys.readouterr()

    assert registered(tmp_path) == []


def test_a_numeric_mobile_column_is_imported_as_a_dialled_number(
    project: Path, tmp_path: Path, capsys
) -> None:
    pytest.importorskip("openpyxl")
    import openpyxl

    path = tmp_path / "numeric.xlsx"
    workbook = openpyxl.Workbook()
    worksheet = workbook.active
    worksheet.append(["姓名", "手機"])
    worksheet.append(["吳孟儒", 912000111])
    workbook.save(path)

    main(["terms", "import", str(path), "--yes", "--materialize", "--project", str(project)])
    capsys.readouterr()

    terms = (project / ".pii-guard" / "terms.txt").read_text(encoding="utf-8")
    assert "TW_MOBILE\t0912000111" in terms


def test_a_reload_that_loaded_nothing_is_reported_as_a_warning(
    table: Path, project: Path, capsys, monkeypatch
) -> None:
    """A reload of zero terms must not read like a success."""

    monkeypatch.setattr(
        "pii_guard.hookd.__main__._reload_service", lambda _config: {"ok": True, "terms": 0}
    )

    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    captured = capsys.readouterr()
    assert "注意：保護服務載入了 0 筆" in captured.err
    assert "已重新載入" not in captured.out


def test_a_reload_that_loaded_terms_is_reported_plainly(
    table: Path, project: Path, capsys, monkeypatch
) -> None:
    monkeypatch.setattr(
        "pii_guard.hookd.__main__._reload_service", lambda _config: {"ok": True, "terms": 9}
    )

    main(["terms", "import", str(table), "--yes", "--project", str(project)])

    captured = capsys.readouterr()
    assert "保護服務已重新載入，共 9 筆。" in captured.out
    assert captured.err == ""
