import importlib
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SERVICES_PATH = Path(__file__).parents[1] / "nginxdp" / "sbin"
assert SERVICES_PATH.exists()
sys.path.insert(0, str(SERVICES_PATH))

dataauth = importlib.import_module("dataauth")
nginxdp = importlib.import_module("nginxdp")
nginxdp_config = importlib.import_module("nginxdp_config")


def _write_config(path, body):
    path.write_text("[nginx]\n" + body, encoding="utf-8")
    return path


def test_load_config_uses_defaults_and_custom_paths(tmp_path):
    defaults = _write_config(tmp_path / "default.ini", "")
    config = nginxdp_config.load_config(str(defaults))
    assert config.port == 9681
    assert not config.ssl_enabled
    assert config.data_dir == Path("/srv/dataplacement")
    assert config.log_dir == Path("/var/log/dataplacement")

    custom = _write_config(
        tmp_path / "custom.ini",
        "port = 8443\n"
        "ssl_enabled = true\n"
        "ssl_certificate = /etc/certs/host.pem\n"
        "ssl_certificate_key = /etc/certs/host.key\n"
        "data_dir = /srv/custom-data\n"
        "log_dir = /var/log/custom-data\n",
    )
    config = nginxdp_config.load_config(str(custom))
    assert config.port == 8443
    assert config.ssl_enabled
    assert config.ssl_certificate == "/etc/certs/host.pem"
    assert config.ssl_certificate_key == "/etc/certs/host.key"
    assert config.data_dir == Path("/srv/custom-data")
    assert config.log_dir == Path("/var/log/custom-data")


@pytest.mark.parametrize(
    "body",
    [
        "ssl_enabled = true\nssl_certificate = /cert.pem\n",
        "port = 65536\n",
        "data_dir = relative/path\n",
        "log_dir = /var/log/nginx; include /tmp/evil\n",
    ],
)
def test_load_config_rejects_invalid_settings(tmp_path, body):
    config_file = _write_config(tmp_path / "invalid.ini", body)
    with pytest.raises(ValueError):
        nginxdp_config.load_config(str(config_file))


def test_render_config_adds_only_configured_listen_and_ssl_directives(tmp_path):
    config_file = _write_config(
        tmp_path / "nginxdp.ini",
        "port = 8080\n" "data_dir = /custom/data\n" "log_dir = /custom/log\n",
    )
    config = nginxdp_config.load_config(str(config_file))
    template = nginxdp.TEMPLATE_PATH.read_text(encoding="utf-8")

    rendered = nginxdp.render_config(template, config)
    assert "listen 8080;" in rendered
    assert "listen 8080 ssl;" not in rendered
    assert "ssl_certificate " not in rendered
    assert 'root "/custom/data";' in rendered
    assert 'error_log  "/custom/log/error.log";' in rendered
    assert "unix:/custom/data/dataauth.sock" in rendered

    config_file.write_text(
        "[nginx]\n"
        "ssl_enabled = true\n"
        "ssl_certificate = /etc/certs/host.pem\n"
        "ssl_certificate_key = /etc/certs/host.key\n",
        encoding="utf-8",
    )
    ssl_config = nginxdp_config.load_config(str(config_file))
    ssl_rendered = nginxdp.render_config(template, ssl_config)
    assert "listen 9681 ssl;" in ssl_rendered
    assert 'ssl_certificate "/etc/certs/host.pem";' in ssl_rendered
    assert 'ssl_certificate_key "/etc/certs/host.key";' in ssl_rendered


def test_files_upload_location_allows_head_and_uses_staging_root():
    template = nginxdp.TEMPLATE_PATH.read_text(encoding="utf-8")
    location_start = template.index("        location /files_upload/ {")
    location_end = template.index("\n        }", location_start)
    upload_location = template[location_start:location_end]

    assert (
        "add_header Access-Control-Allow-Methods "
        '"GET, HEAD, POST, PUT, DELETE, OPTIONS" always;'
    ) in upload_location
    assert 'root "@DATA_DIR@";' in upload_location


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_dataauth_allows_reading_own_staged_uploads(monkeypatch, method):
    handler = object.__new__(dataauth.AuthHandler)
    handler.headers = {
        "X-Original-URI": "/files_upload/alice@example.net/report.txt",
        "X-Original-Method": method,
        "Authorization": "Bearer valid.token.signature",
    }
    handler.client_address = None
    responses = []
    ping_methods = []

    monkeypatch.setattr(dataauth, "token_looks_valid", lambda token: True)
    monkeypatch.setattr(
        dataauth,
        "ping_with_idtoken",
        lambda token, ping_method: (
            ping_methods.append(ping_method) or (True, "alice@example.net")
        ),
    )
    handler.send_response = lambda status, message=None, logprefix="": responses.append(
        (status, message)
    )
    handler.end_headers = lambda: None

    handler.do_GET()

    assert ping_methods == ["read"]
    assert responses[0][0] == 200


def test_dataauth_denies_head_on_another_users_staged_upload(monkeypatch):
    handler = object.__new__(dataauth.AuthHandler)
    handler.headers = {
        "X-Original-URI": "/files_upload/bob@example.net/report.txt",
        "X-Original-Method": "HEAD",
        "Authorization": "Bearer valid.token.signature",
    }
    handler.client_address = None
    responses = []

    monkeypatch.setattr(dataauth, "token_looks_valid", lambda token: True)
    monkeypatch.setattr(
        dataauth,
        "ping_with_idtoken",
        lambda token, ping_method: (True, "alice@example.net"),
    )
    handler.send_response = lambda status, message=None, logprefix="": responses.append(
        (status, message)
    )
    handler.end_headers = lambda: None

    handler.do_GET()

    assert responses[0][0] == 403


def test_prepare_service_paths_creates_configured_directories(tmp_path, monkeypatch):
    config_file = _write_config(
        tmp_path / "nginxdp.ini",
        "data_dir = {}\nlog_dir = {}\n".format(tmp_path / "data", tmp_path / "logs"),
    )
    config = nginxdp_config.load_config(str(config_file))
    chowned = []
    monkeypatch.setattr(nginxdp.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        nginxdp.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=123),
    )
    monkeypatch.setattr(
        nginxdp.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=456)
    )
    monkeypatch.setattr(
        nginxdp.os,
        "chown",
        lambda path, uid, gid, **kwargs: chowned.append((Path(path), uid, gid)),
    )

    nginxdp._prepare_service_paths(config)

    assert all(
        (config.data_dir / name).is_dir()
        for name in ("", "files", "files_upload", "files_upload_tmp")
    )
    assert (config.log_dir / "access.log").is_file()
    assert (config.log_dir / "error.log").is_file()
    assert (config.data_dir, 123, 456) in chowned
    assert (config.log_dir, 123, 456) in chowned


def test_drop_to_nginx_changes_identity_only_when_root(monkeypatch):
    calls = []
    monkeypatch.setattr(nginxdp.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        nginxdp.pwd,
        "getpwnam",
        lambda name: SimpleNamespace(pw_name=name, pw_uid=123),
    )
    monkeypatch.setattr(
        nginxdp.grp, "getgrnam", lambda name: SimpleNamespace(gr_gid=456)
    )
    monkeypatch.setattr(
        nginxdp.os, "initgroups", lambda *args: calls.append(("init", args))
    )
    monkeypatch.setattr(nginxdp.os, "setgid", lambda gid: calls.append(("gid", gid)))
    monkeypatch.setattr(nginxdp.os, "setuid", lambda uid: calls.append(("uid", uid)))

    nginxdp._drop_to_nginx()
    assert calls == [
        ("init", ("nginx", 456)),
        ("gid", 456),
        ("uid", 123),
    ]

    calls.clear()
    monkeypatch.setattr(nginxdp.os, "geteuid", lambda: 1000)
    nginxdp._drop_to_nginx()
    assert calls == []


def test_dataauth_uses_configured_socket_and_log_paths(tmp_path, monkeypatch):
    config_file = _write_config(
        tmp_path / "nginxdp.ini",
        "data_dir = /custom/data\n" "log_dir = {}\n".format(tmp_path),
    )
    server_args = []

    class FakeServer:
        def __init__(self, path, handler):
            server_args.append((path, handler))

        def serve_forever(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(dataauth, "UnixDomainHTTPServer", FakeServer)
    monkeypatch.setattr(dataauth.logger, "handlers", [])
    monkeypatch.setattr(dataauth.logger, "propagate", True)

    assert dataauth.main(["--config", str(config_file)]) is None
    assert server_args == [("/custom/data/dataauth.sock", dataauth.AuthHandler)]
    assert (tmp_path / "dataauth.log").exists()
    for handler in dataauth.logger.handlers:
        handler.close()


def test_dataauth_socket_cli_argument_overrides_configured_data_root(
    tmp_path, monkeypatch
):
    config_file = _write_config(
        tmp_path / "nginxdp.ini",
        f"data_dir = /custom/data\nlog_dir = {tmp_path}\n",
    )
    server_args = []

    class FakeServer:
        def __init__(self, path, handler):
            server_args.append(path)

        def serve_forever(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(dataauth, "UnixDomainHTTPServer", FakeServer)
    monkeypatch.setattr(dataauth.logger, "handlers", [])

    dataauth.main(["--config", str(config_file), "/tmp/override.sock"])
    assert server_args == ["/tmp/override.sock"]
    for handler in dataauth.logger.handlers:
        handler.close()


def test_existing_config_dir_is_not_modified(tmp_path):
    config_dir = tmp_path / "shared"
    config_dir.mkdir()
    config_dir.chmod(0o755)
    nginxdp._write_generated_config("x", config_dir / "nginx.conf")
    assert os.stat(config_dir).st_mode & 0o777 == 0o755


def test_check_config_readable_warns_when_unreadable(tmp_path, capsys):
    missing = tmp_path / "nope.conf"
    assert nginxdp.check_config_readable(missing) is False
    assert "warning" in capsys.readouterr().err
    present = tmp_path / "ok.conf"
    present.write_text("x")
    assert nginxdp.check_config_readable(present) is True
