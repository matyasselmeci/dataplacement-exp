import hashlib
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT_PATH = Path(__file__).parents[1] / "nginxdp" / "sbin" / "uploadmover.py"
sys.path.insert(0, str(SCRIPT_PATH.parent))
SPEC = importlib.util.spec_from_file_location("uploadmover", SCRIPT_PATH)
assert SPEC is not None
assert SPEC.loader is not None
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


@pytest.mark.parametrize(
    "first,second",
    [("alice", "alice@example.net"), ("alice@example.net", "alice")],
)
def test_read_mapfile_deduplicates_qualified_ids(tmp_path, monkeypatch, first, second):
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: "example.net")
    monkeypatch.setattr(uploadmover, "_read_uid_min", lambda: 1000)
    _fake_user(monkeypatch)
    warnings = []
    monkeypatch.setattr(
        uploadmover.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )
    mapfile = tmp_path / "mapfile"
    mapfile.write_text(
        f"{first} alice\n{second} other\nalice@elsewhere.net other\n",
        encoding="utf-8",
    )

    assert uploadmover.read_dataplacement_mapfile(mapfile) == [
        uploadmover.UserMapping("alice@example.net", "alice"),
        uploadmover.UserMapping("alice@elsewhere.net", "other"),
    ]
    assert len(warnings) == 1
    assert "duplicate AP user ID" in warnings[0]
    assert "line 2" in warnings[0]


def test_rejected_mapping_does_not_reserve_qualified_id(tmp_path, monkeypatch):
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: "example.net")
    monkeypatch.setattr(uploadmover, "_read_uid_min", lambda: 1000)
    users = {"system": 999, "alice": 1200}
    monkeypatch.setattr(
        uploadmover.pwd,
        "getpwnam",
        lambda username: SimpleNamespace(pw_uid=users[username]),
    )
    mapfile = tmp_path / "mapfile"
    mapfile.write_text("alice system\nalice@example.net alice\n", encoding="utf-8")

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
    chowns = []
    monkeypatch.setattr(
        uploadmover.os,
        "chown",
        lambda path, uid, gid, **kwargs: chowns.append((Path(path), uid, gid)),
    )
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    files_dir.mkdir()
    source = upload_dir / "alice@example.net" / "nested" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("uploaded data", encoding="utf-8")
    (upload_dir / "alice@example.net" / "empty" / "nested").mkdir(parents=True)
    source.chmod(0o600)
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=upload_dir,
        period=15,
        oneshot=True,
    )
    original_move = uploadmover.move_and_chown_file

    def check_checksum_before_move(src, dst, owner, options):
        checksum = files_dir / "alice@example.net/.__meta/checksums/nested/report.txt"
        assert (
            checksum.read_text() == hashlib.sha256(b"uploaded data").hexdigest() + "\n"
        )
        assert Path(src).exists()
        original_move(src, dst, owner, options)

    monkeypatch.setattr(uploadmover, "move_and_chown_file", check_checksum_before_move)

    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )

    destination = files_dir / "alice@example.net" / "nested" / "report.txt"
    assert successes == ["alice@example.net/nested/report.txt"]
    assert failures == []
    assert destination.read_text(encoding="utf-8") == "uploaded data"
    checksum = files_dir / "alice@example.net" / ".__meta/checksums/nested/report.txt"
    assert checksum.read_text() == hashlib.sha256(b"uploaded data").hexdigest() + "\n"
    assert stat.S_IMODE(checksum.stat().st_mode) == 0o644
    for root in (upload_dir, files_dir):
        metadata = root / "alice@example.net" / ".__meta"
        assert stat.S_IMODE(metadata.stat().st_mode) == 0o755
        assert stat.S_IMODE((metadata / "checksums").stat().st_mode) == 0o755
        assert (metadata, 0, 4321) in chowns
    assert not source.exists()
    assert not (upload_dir / "alice@example.net" / "nested").exists()
    assert upload_dir.is_dir()
    assert stat.S_IMODE(destination.stat().st_mode) & stat.S_IRGRP
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o770


def test_chowns_upload_in_place_when_roots_are_the_same(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    source = files_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir()
    source.write_text("uploaded data", encoding="utf-8")
    empty_dir = source.parent / "empty"
    empty_dir.mkdir()
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
    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )

    assert successes == ["alice@example.net/report.txt"]
    assert failures == []
    assert source.read_text(encoding="utf-8") == "uploaded data"
    assert empty_dir.is_dir()
    assert source in chowned_paths
    assert stat.S_IMODE(source.stat().st_mode) == 0o600
    checksum = source.parent / ".__meta/checksums/report.txt"
    assert checksum.read_text() == hashlib.sha256(b"uploaded data").hexdigest() + "\n"
    assert uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    ) == (["alice@example.net/report.txt"], [])
    assert not (source.parent / ".__meta/checksums/.__meta").exists()


def test_failed_replacement_restores_previous_checksum(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: None)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    upload_dir = tmp_path / "files_upload"
    source = upload_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("first")
    opts = uploadmover.Options(tmp_path / "mapfile", files_dir, upload_dir, 5, True)
    mapping = [uploadmover.UserMapping("alice@example.net", "alice")]
    assert uploadmover.move_uploaded_files(mapping, opts)[1] == []
    checksum = files_dir / "alice@example.net" / ".__meta/checksums/report.txt"
    previous = checksum.read_text()
    source.write_text("second")
    original_move = uploadmover.move_and_chown_file
    monkeypatch.setattr(
        uploadmover,
        "move_and_chown_file",
        lambda *args: (_ for _ in ()).throw(OSError("move failed")),
    )

    assert uploadmover.move_uploaded_files(mapping, opts) == (
        [],
        ["alice@example.net/report.txt"],
    )
    assert checksum.read_text() == previous
    assert source.read_text() == "second"
    assert (files_dir / "alice@example.net/report.txt").read_text() == "first"
    monkeypatch.setattr(uploadmover, "move_and_chown_file", original_move)
    assert uploadmover.move_uploaded_files(mapping, opts) == (
        ["alice@example.net/report.txt"],
        [],
    )
    assert checksum.read_text() == hashlib.sha256(b"second").hexdigest() + "\n"


def test_rejects_symlinked_metadata_directory(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    upload_dir = tmp_path / "files_upload"
    source = upload_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("data")
    outside = tmp_path / "outside"
    outside.mkdir()
    (source.parent / ".__meta").symlink_to(outside, target_is_directory=True)
    opts = uploadmover.Options(tmp_path / "mapfile", files_dir, upload_dir, 5, True)

    uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )
    assert source.exists()
    assert list(outside.iterdir()) == []


def test_rejects_preexisting_metadata_owned_by_another_user(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    monkeypatch.setattr(uploadmover.os, "geteuid", lambda: os.getuid() + 1)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    upload_dir = tmp_path / "files_upload"
    source = upload_dir / "alice@example.net" / "report.txt"
    source.parent.mkdir(parents=True)
    source.write_text("data")
    (source.parent / ".__meta").mkdir()
    opts = uploadmover.Options(tmp_path / "mapfile", files_dir, upload_dir, 5, True)

    uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    )
    assert source.exists()
    assert not (files_dir / "alice@example.net/report.txt").exists()


@pytest.mark.parametrize(
    ("uid_domain", "expected_alias"),
    [
        ("chtc.wisc.edu", True),
        ("example.net", False),
        (None, False),
    ],
)
def test_creates_unqualified_alias_only_for_uid_domain(
    tmp_path, monkeypatch, uid_domain, expected_alias
):
    _fake_user(monkeypatch)
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: uid_domain)
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    files_dir.mkdir()
    upload_dir.mkdir()
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=upload_dir,
        period=15,
        oneshot=True,
    )

    successes, failures = uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("matyas@chtc.wisc.edu", "matyas")], opts
    )

    alias = files_dir / "matyas"
    target_dir = files_dir / "matyas@chtc.wisc.edu"
    assert successes == []
    assert failures == []
    assert alias.is_symlink() is expected_alias
    if expected_alias:
        assert os.readlink(str(alias)) == "matyas@chtc.wisc.edu"
        assert target_dir.is_dir()
    else:
        assert not target_dir.exists()


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


def test_cleanup_preserves_failed_uploads_and_symlinked_directories(
    tmp_path, monkeypatch
):
    _fake_user(monkeypatch)
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: None)
    files_dir = tmp_path / "files"
    upload_dir = tmp_path / "files_upload"
    files_dir.mkdir()
    user_dir = upload_dir / "alice@example.net"
    failed = user_dir / "failed" / "report.txt"
    failed.parent.mkdir(parents=True)
    failed.write_text("uploaded data", encoding="utf-8")
    moved = user_dir / "moved" / "report.txt"
    moved.parent.mkdir()
    moved.write_text("other data", encoding="utf-8")
    (user_dir / "link").symlink_to(failed.parent, target_is_directory=True)
    destination = files_dir / "alice@example.net" / "failed"
    destination.mkdir(parents=True)
    (destination / "report.txt").symlink_to(failed)
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

    assert successes == ["alice@example.net/moved/report.txt"]
    assert sorted(failures) == [
        "alice@example.net/failed/report.txt",
        "alice@example.net/link",
    ]
    assert failed.read_text(encoding="utf-8") == "uploaded data"
    assert (user_dir / "link").is_symlink()
    assert not moved.parent.exists()
    assert user_dir.is_dir()


def test_cleanup_logs_unexpected_removal_errors(tmp_path, monkeypatch):
    _fake_user(monkeypatch)
    monkeypatch.setattr(uploadmover, "_get_uid_domain", lambda: None)
    files_dir = tmp_path / "files"
    files_dir.mkdir()
    upload_dir = tmp_path / "files_upload"
    user_dir = upload_dir / "alice@example.net"
    user_dir.mkdir(parents=True)
    opts = uploadmover.Options(
        mapfile=tmp_path / "mapfile",
        nginx_files_dir=files_dir,
        nginx_upload_dir=upload_dir,
        period=15,
        oneshot=True,
    )
    warnings = []
    monkeypatch.setattr(
        uploadmover.logger,
        "warning",
        lambda message, *args: warnings.append(message % args),
    )

    def deny_removal(path):
        raise PermissionError("permission denied")

    monkeypatch.setattr(Path, "rmdir", deny_removal)

    assert uploadmover.move_uploaded_files(
        [uploadmover.UserMapping("alice@example.net", "alice")], opts
    ) == ([], [])
    assert user_dir.is_dir()
    assert len(warnings) == 1
    assert str(user_dir) in warnings[0]


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
