"""Shared configuration for the data-placement nginx and helper services."""

import configparser
import os
import pathlib
from typing import NamedTuple

DEFAULT_CONFIG_PATH = "/etc/nginxdp.ini"
DEFAULT_PORT = 9681
DEFAULT_DATA_DIR = "/srv/dataplacement"
DEFAULT_LOG_DIR = "/var/log/dataplacement"
DEFAULT_GENERATED_CONFIG = "/run/nginxdp/nginx.conf"
DEFAULT_UPLOADMOVER_PERIOD = 5  # seconds


class NginxDPConfig(NamedTuple):
    """Validated settings shared by nginx, dataauth, and uploadmover."""

    port: int
    ssl_enabled: bool
    ssl_certificate: str
    ssl_certificate_key: str
    data_dir: pathlib.Path
    log_dir: pathlib.Path
    generated_config: pathlib.Path = pathlib.Path(DEFAULT_GENERATED_CONFIG)
    uploadmover_period: int = DEFAULT_UPLOADMOVER_PERIOD


def _absolute_path(value: str, name: str) -> pathlib.Path:
    """Validate a path that will be interpolated as an nginx directive value."""
    if not value or not os.path.isabs(value):
        raise ValueError(f"{name} must be an absolute path")
    if any(
        ord(char) < 32 or char in ('"', "\\", ";", "$", "{", "}", "@") for char in value
    ):
        raise ValueError(f"{name} contains a character unsafe for nginx config")
    return pathlib.Path(value)


def load_config(config_path: str = DEFAULT_CONFIG_PATH) -> NginxDPConfig:
    """Read and validate the shared ConfigParser-format service configuration."""
    parser = configparser.ConfigParser(interpolation=None)
    with open(config_path, encoding="utf-8") as config_file:
        parser.read_file(config_file)

    if not parser.has_section("nginx"):
        raise ValueError("configuration is missing the [nginx] section")

    try:
        port = parser.getint("nginx", "port", fallback=DEFAULT_PORT)
        ssl_enabled = parser.getboolean("nginx", "ssl_enabled", fallback=False)
        ssl_certificate = parser.get("nginx", "ssl_certificate", fallback="").strip()
        ssl_certificate_key = parser.get(
            "nginx", "ssl_certificate_key", fallback=""
        ).strip()
        data_dir = _absolute_path(
            parser.get("nginx", "data_dir", fallback=DEFAULT_DATA_DIR).strip(),
            "data_dir",
        )
        log_dir = _absolute_path(
            parser.get("nginx", "log_dir", fallback=DEFAULT_LOG_DIR).strip(),
            "log_dir",
        )
        generated_config = _absolute_path(
            parser.get(
                "nginx", "generated_config", fallback=DEFAULT_GENERATED_CONFIG
            ).strip(),
            "generated_config",
        )
        uploadmover_period = parser.getint(
            "nginx", "uploadmover_period", fallback=DEFAULT_UPLOADMOVER_PERIOD
        )
    except (configparser.Error, ValueError) as err:
        raise ValueError(f"invalid [nginx] configuration: {err}") from err

    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if uploadmover_period <= 0:
        raise ValueError("uploadmover_period must be a positive number of seconds")
    if ssl_enabled:
        if not ssl_certificate or not ssl_certificate_key:
            raise ValueError(
                "ssl_certificate and ssl_certificate_key are required when "
                "ssl_enabled is true"
            )
        _absolute_path(ssl_certificate, "ssl_certificate")
        _absolute_path(ssl_certificate_key, "ssl_certificate_key")

    return NginxDPConfig(
        port,
        ssl_enabled,
        ssl_certificate,
        ssl_certificate_key,
        data_dir,
        log_dir,
        generated_config,
        uploadmover_period,
    )
