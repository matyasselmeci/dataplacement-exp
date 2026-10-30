#!/usr/bin/env python3
"""Generate the data-placement nginx configuration and replace this process."""

import argparse
import grp
import os
import pathlib
import pwd
import sys

from nginxdp_config import DEFAULT_CONFIG_PATH, load_config

NGINX_BINARY = "/usr/sbin/nginx"
_PREFIX = pathlib.Path(__file__).parent.parent
TEMPLATE_PATH = _PREFIX / "share/dataplacement/nginx-dataplacement.conf.template"
if not TEMPLATE_PATH.is_file():
    # Keep source-tree tests working while installed scripts use the shared-data path.
    TEMPLATE_PATH = _PREFIX / "nginx-dataplacement.conf.template"


def render_config(template: str, config) -> str:
    """Substitute validated settings into the packaged nginx configuration template."""
    data_dir = str(config.data_dir)
    log_dir = str(config.log_dir)
    ssl_directives = ""
    listen = f"listen {config.port};"
    if config.ssl_enabled:
        listen = f"listen {config.port} ssl;"
        ssl_directives = (
            '        ssl_certificate "{}";\n' '        ssl_certificate_key "{}";\n'
        ).format(config.ssl_certificate, config.ssl_certificate_key)

    substitutions = {
        "@DATA_DIR@": data_dir,
        "@LOG_DIR@": log_dir,
        "@LISTEN_DIRECTIVE@": listen,
        "@SSL_DIRECTIVES@": ssl_directives.rstrip(),
    }
    for marker, value in substitutions.items():
        template = template.replace(marker, value)
    if any(marker in template for marker in substitutions):
        raise ValueError("nginx template contains an unresolved setting")
    return template


def _drop_to_nginx() -> None:
    """Drop root privileges, including supplementary groups, before execing nginx."""
    if os.geteuid() != 0:
        return
    nginx_user = pwd.getpwnam("nginx")
    nginx_group = grp.getgrnam("nginx")
    os.initgroups(nginx_user.pw_name, nginx_group.gr_gid)
    os.setgid(nginx_group.gr_gid)
    os.setuid(nginx_user.pw_uid)


def _prepare_service_paths(config) -> None:
    """Create missing configured storage and log paths before dropping root."""
    if os.geteuid() != 0:
        return

    nginx_user = pwd.getpwnam("nginx")
    nginx_group = grp.getgrnam("nginx")
    root_gid = grp.getgrnam("root").gr_gid
    for path in (
        config.data_dir,
        config.data_dir / "files",
        config.data_dir / "files_upload",
        config.data_dir / "files_upload_tmp",
    ):
        created = not path.exists()
        path.mkdir(parents=True, exist_ok=True)
        if created:
            os.chown(path, nginx_user.pw_uid, nginx_group.gr_gid)
            os.chmod(path, 0o755)

    log_dir_created = not config.log_dir.exists()
    config.log_dir.mkdir(parents=True, exist_ok=True)
    if log_dir_created:
        os.chown(config.log_dir, nginx_user.pw_uid, root_gid)
        os.chmod(config.log_dir, 0o751)
    for filename in ("access.log", "error.log"):
        log_file = config.log_dir / filename
        if log_file.is_symlink():
            raise ValueError(f"nginx log path must not be a symlink: {log_file}")
        with open(log_file, "a", encoding="utf-8"):
            pass
        os.chown(log_file, nginx_user.pw_uid, root_gid, follow_symlinks=False)


def _write_generated_config(rendered: str, config_path: pathlib.Path) -> None:
    """Write the nginx config with file mode 640 (root:nginx when run as root).

    A directory this function creates is set to root:nginx 750. A pre-existing
    directory is left untouched, since it may be shared (e.g. /run itself);
    check_config_readable() warns if nginx cannot read the result.
    """
    config_dir = config_path.parent
    created = not config_dir.exists()
    config_dir.mkdir(parents=True, exist_ok=True)
    is_root = os.geteuid() == 0
    nginx_gid = grp.getgrnam("nginx").gr_gid if is_root else -1
    if created:
        if is_root:
            os.chown(config_dir, 0, nginx_gid)
        os.chmod(config_dir, 0o750)

    # Write beside the target and rename so nginx never sees a partial file.
    partial = config_dir / (config_path.name + ".new")
    descriptor = os.open(
        partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
            config_file.write(rendered)
            if is_root:
                os.fchown(config_file.fileno(), 0, nginx_gid)
            os.fchmod(config_file.fileno(), 0o640)
        os.replace(partial, config_path)
    except OSError:
        partial.unlink(missing_ok=True)
        raise


def check_config_readable(config_path: pathlib.Path) -> bool:
    """Warn on stderr if the current (post-drop) user cannot read the config.

    Must run after _drop_to_nginx() so os.access reflects the nginx user's
    permissions, including search access on every parent directory.

    Returns:
        True if the file is readable.
    """
    if os.access(config_path, os.R_OK):
        return True
    print(
        f"nginxdp: warning: nginx will not be able to read {config_path}; "
        "check permissions on it and its parent directories",
        file=sys.stderr,
    )
    return False


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
        template = TEMPLATE_PATH.read_text(encoding="utf-8")
        rendered = render_config(template, config)
        _write_generated_config(rendered, config.generated_config)
        _prepare_service_paths(config)
        _drop_to_nginx()
        check_config_readable(config.generated_config)
    except (OSError, ValueError, KeyError) as err:
        print(f"nginxdp: {err}", file=sys.stderr)
        return 1

    try:
        os.execv(
            NGINX_BINARY,
            [
                NGINX_BINARY,
                "-c",
                str(config.generated_config),
                "-e",
                os.path.join(config.log_dir, "nginx.log"),
            ],
        )
    except OSError as err:
        print(f"nginxdp: unable to execute nginx: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
