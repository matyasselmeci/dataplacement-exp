import importlib.util
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT_PATH = (
    Path(__file__).parents[1]
    / "nginxdp"
    / "sbin"
    / "uploadmover.py"
)
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("uploadmover", SCRIPT_PATH)
uploadmover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(uploadmover)


def _fake_user(monkeypatch, uid=1234):
    monkeypatch.setattr(
        uploadmover.pwd,
        "getpwnam",
        lambda username: SimpleNamespace(pw_uid=uid),
    )
    monkeypatch.setattr(uploadmover, "_nginx_gid", lambda: 4321)
    monkeypatch.setattr(uploadmover.os, "chown", lambda *args, **kwargs: None)


def test_reads_uid_min_from_login_defs(tmp_path):
    login_defs = tmp_path / "login.defs"
    login_defs.write_text("# policy\nUID_MIN 1100\n", encoding="utf-8")

    assert uploadmover._read_uid_min(login_defs) == 1100


def test_read_mapfile_filters_invalid_entries(tmp_path, monkeypatch):
    users = {"alice": 1200, "system": 999}
    monkeypatch.setattr(
        uploadmover.pwd,
        "getpwnam",
        lambda username: SimpleNamespace(pw_uid=users[username]),
    )
    mapfile = tmp_path / "mapfile"
    mapfile.write_text(
        "# comment\n"
        "alice@example.net alice\n"
        "alice@example.net system\n"
        "../outside alice\n"
        "broken\n"
        "system@example.net system\n"
        "missing@example.net nobody\n",
        encoding="utf-8",
    )

    assert uploadmover.read_dataplacement_mapfile(mapfile) == [
        uploadmover.UserMapping("alice@example.net", "alice")
    ]


def test_warns_once_for_empty_or_all_invalid_mapfile_content(tmp_path, monkeypatch):
    warnings = []
    monkeypatch.setattr(uploadmover.logger, "propagate", False)
    monkeypatch.setattr(
        uploadmover.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )
    mapfile = tmp_path / "mapfile"
    mapfile.write_text("# only a comment\n\n", encoding="utf-8")
    empty_mappings, empty_entries, empty_hash = uploadmover._read_dataplacement_mapfile(
        mapfile
    )

    previous_hash = uploadmover._warn_on_empty_mapfile(
        mapfile, empty_mappings, empty_entries, empty_hash, None
    )
    uploadmover._warn_on_empty_mapfile(
        mapfile, empty_mappings, empty_entries, empty_hash, previous_hash
    )
    assert len(warnings) == 1
    assert str(mapfile) in warnings[0]
    assert "contains no entries" in warnings[0]

    mapfile.write_text("not a valid mapping line\n", encoding="utf-8")
    invalid_mappings, invalid_entries, invalid_hash = (
        uploadmover._read_dataplacement_mapfile(mapfile)
    )
    warnings.clear()
    previous_hash = uploadmover._warn_on_empty_mapfile(
        mapfile, invalid_mappings, invalid_entries, invalid_hash, previous_hash
    )
    uploadmover._warn_on_empty_mapfile(
        mapfile, invalid_mappings, invalid_entries, invalid_hash, previous_hash
    )

    assert len(warnings) == 1
    assert str(mapfile) in warnings[0]
    assert "all entries were filtered out as invalid" in warnings[0]


def test_moves_upload_and_sets_nginx_read_access(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    files_dir.mkdir()
    source = upload_dir / "alice@example.net" / "nested" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("uploaded data", encoding="utf-8")
    source.chmod(0o600)
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=upload_dir,
        period=15,
        oneshot=True,
    )

    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )

    destination = files_dir / "alice@example.net" / "nested" / "report.txt"
    assert successes == ["alice@example.net/nested/report.txt"]
    assert failures == []
    assert destination.read_text(encoding="utf-8") == "uploaded data"
    assert not source.exists()
    assert stat.S_IMODE(destination.stat().st_mode) & stat.S_IRGRP
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o770


def test_chowns_upload_in_place_when_roots_are_the_same(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    source = files_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir()
    source.write_text("uploaded data", encoding="utf-8")
    source.chmod(0o600)
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=files_dir,
        period=15,
        oneshot=True,
    )
    chowned_paths = []
    monkeypatch.setattr(
        uploadmover.os,
        "chown",
        lambda path, uid, gid, **kwargs: chowned_paths.append(Path(path)),
    )
    monkeypatch.setattr(
        uploadmover.os,
        "replace",
        lambda *args: pytest.fail("same-root uploads must not be moved"),
    )

    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )

    assert successes == ["alice@example.net/report.txt"]
    assert failures == []
    assert source.read_text(encoding="utf-8") == "uploaded data"
    assert source in chowned_paths
    assert stat.S_IMODE(source.stat().st_mode) == 0o600


def test_refuses_destination_symlink(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    files_dir.mkdir()
    source = upload_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("uploaded data", encoding="utf-8")
    other_user_dir = files_dir / "other"
    other_user_dir.mkdir()
    (files_dir / "alice@example.net").symlink_to(other_user_dir)
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=upload_dir,
        period=15,
        oneshot=True,
    )

    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )

    assert successes == []
    assert failures == ["alice@example.net/report.txt"]
    assert source.exists()
    assert not (other_user_dir / "report.txt").exists()


def test_get_options_parses_flags_and_rejects_invalid_period(tmp_path):
    config = tmp_path / "nginxdp.ini"
    config.write_text(
        "[nginx]\n"
        "data_dir = /srv/nginx-dataplacement\n"
        "log_dir = /var/log/dataplacement\n",
        encoding="utf-8",
    )
    opts = uploadmover.get_options(
        [
            "--config",
            str(config),
            "--mapfile",
            "/tmp/map",
            "--nginx-files-dir",
            "/tmp/files",
            "--nginx-upload-dir",
            "/tmp/uploads",
            "--period",
            "3",
            "--log-file",
            "/tmp/uploadmover.log",
            "--oneshot",
        ]
    )
    assert opts.period == 3
    assert opts.oneshot
    assert opts.log_path == Path("/tmp/uploadmover.log")
    assert uploadmover.get_options(
        ["--config", str(config), "--log-path", "/tmp/other.log"]
    ).log_path == Path("/tmp/other.log")
    with pytest.raises(SystemExit):
        uploadmover.get_options(["--config", str(config), "--period", "0"])


def test_config_values_set_defaults_and_cli_paths_override(tmp_path):
    config = tmp_path / "nginxdp.ini"
    config.write_text(
        "[nginx]\n" "data_dir = /custom/data\n" "log_dir = /custom/logs\n",
        encoding="utf-8",
    )

    opts = uploadmover.get_options(["--config", str(config)])
    assert opts.nginx_files_dir == Path("/custom/data/files")
    assert opts.nginx_upload_dir == Path("/custom/data/files_upload")
    assert opts.log_path == Path("/custom/logs/uploadmover.log")

    overrides = uploadmover.get_options(
        [
            "--config",
            str(config),
            "--nginx-files-dir",
            "/override/files",
            "--nginx-upload-dir",
            "/override/uploads",
            "--log-file",
            "/override/log",
        ]
    )
    assert overrides.nginx_files_dir == Path("/override/files")
    assert overrides.nginx_upload_dir == Path("/override/uploads")
    assert overrides.log_path == Path("/override/log")


def test_oneshot_cli_runs_script(tmp_path):
    mapfile = tmp_path / "mapfile"
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    mapfile.write_text("# no mappings\n", encoding="utf-8")
    files_dir.mkdir()
    upload_dir.mkdir()

    log_path = tmp_path / "uploadmover.py"
    config = tmp_path / "nginxdp.ini"
    config.write_text("[nginx]\n", encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--config",
            str(config),
            "--mapfile",
            str(mapfile),
            "--nginx-files-dir",
            str(files_dir),
            "--nginx-upload-dir",
            str(upload_dir),
            "--log-file",
            str(log_path),
            "--oneshot",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "Starting upload mover" in result.stderr
    assert "Starting upload mover" in log_path.read_text(encoding="utf-8")


def test_period_comes_from_config_unless_cli_overrides(tmp_path):
    config = tmp_path / "nginxdp.ini"
    config.write_text("[nginx]\nuploadmover_period = 7\n", encoding="utf-8")
    assert uploadmover.get_options(["--config", str(config)]).period == 7
    assert (
        uploadmover.get_options(["--config", str(config), "--period", "2"]).period == 2
    )
    config.write_text("[nginx]\n", encoding="utf-8")
    assert uploadmover.get_options(["--config", str(config)]).period == 5
