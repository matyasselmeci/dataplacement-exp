#!/usr/bin/env python3
"""
dataauth.py

Listens on a Unix domain socket for authorization subrequests sent by
Nginx (auth_request); responds with 200 if the request is authorized,
401 if no token is provided, and 403 if the token is not authorized
to perform the requested action.

Makes a callout to condor to validate the token.
"""

# Note: This needs to be EL8 compatible, i.e. Python 3.6. This means:
# typing.List[str] instead of list[str], typing.Optional instead of str | None, etc.

import argparse
import base64
import binascii
import json
import logging
import os
import pwd
import socket
import subprocess as sp
import tempfile
import typing as t
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

from nginxdp_config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_DATA_DIR,
    DEFAULT_LOG_DIR,
    load_config,
)

# Nginx and dataauth both run as the nginx user, so both can use the configured
# data directory for the authorization socket.
SOCKET_PATH = os.path.join(DEFAULT_DATA_DIR, "dataauth.sock")
SOCKET_MODE = 0o660
RUN_TIMEOUT = 30  # seconds
REQUIRED_HEADER_FIELDS = {"alg", "kid"}
REQUIRED_PAYLOAD_FIELDS = {"exp", "iss", "jti"}
LOG_PATH = os.path.join(DEFAULT_LOG_DIR, "dataauth.log")
PATH_PREFIXES = ("/files", "/files_upload")


logger = logging.getLogger("dataauth")


def _decode_base64url_json(segment: str) -> t.Optional[t.Dict[str, t.Any]]:
    """
    Decode one JWT section from base64url and parse it as a JSON object.

    JWT parts are usually unpadded base64url, so we normalize padding before decode.
    """
    if not segment:
        return None

    padded_segment = segment + ("=" * (-len(segment) % 4))

    try:
        raw_data = base64.urlsafe_b64decode(padded_segment)
        parsed_data = json.loads(raw_data)
    except (binascii.Error, json.JSONDecodeError, TypeError, ValueError):
        return None

    return parsed_data if isinstance(parsed_data, dict) else None


def normalize_uri_path(request_uri: str) -> str:
    """
    Normalizes an Nginx $request_uri string by stripping query parameters/fragments,

    percent-decoding characters, resolving dot segments (. and ..), and collapsing
    duplicate slashes.
    """
    # 1. Strip query string (?...) and fragments (#...)
    path = urlsplit(request_uri).path

    # 2. Percent-decode BEFORE path resolution so encoded dot segments (%2e%2e)
    # are converted to '..' and evaluated by normpath rather than bypassed.
    decoded_path = unquote(path)

    # Track trailing slash intent before normpath strips it
    had_trailing_slash = decoded_path.endswith("/") and decoded_path != "/"

    # 3. Resolve relative segments (. / ..) and collapse duplicate slashes (//)
    normalized = os.path.normpath(decoded_path)

    if normalized == ".":
        normalized = "/"

    if had_trailing_slash and not normalized.endswith("/"):
        normalized += "/"

    return normalized


def is_uri_allowed(request_uri: str, allowed_prefix: str) -> bool:
    """
    Safely checks if the requested URI stays within an allowed directory prefix.

    Returns False if path traversal or null-byte injection is attempted.
    """
    # Reject null bytes to prevent C-library string truncation vulnerabilities downstream
    if "\x00" in request_uri or "%00" in request_uri.lower():
        return False

    norm_path = normalize_uri_path(request_uri)
    norm_prefix = os.path.normpath(allowed_prefix)

    # posixpath.commonpath prevents partial directory prefix matching
    # (e.g., /static_secret matching /static)
    try:
        common = os.path.commonpath([norm_path, norm_prefix])
        return common == norm_prefix
    except ValueError:
        return False


def token_looks_valid(token: str) -> bool:
    """
    Perform a fast token shape check to avoid expensive condor_ping callouts.

    This validates only structure and required fields; it does not verify signature.
    """
    token_parts = token.split(".")
    if len(token_parts) != 3:
        return False

    header_data = _decode_base64url_json(token_parts[0])
    payload_data = _decode_base64url_json(token_parts[1])
    signature_part = token_parts[2]

    if not header_data or not payload_data or not signature_part:
        return False

    return REQUIRED_HEADER_FIELDS.issubset(
        header_data
    ) and REQUIRED_PAYLOAD_FIELDS.issubset(payload_data)


def run_with_idtoken(
    cmd: t.List[str],
    idtoken: str,
    timeout=RUN_TIMEOUT,
) -> sp.CompletedProcess:
    """
    Run a command with a timeout, logging its stdout and stderr, and returning a CompletedProcess.
    Create a temporary directory and write a token there; force token auth.

    Args:
        cmd: The command to run (as a list of str)
        idtoken: The contents of the IDTOKEN to use for auth, as a string
        timeout: Timeout in seconds

    Returns:
        The CompletedProcess returned by subprocess.run
    """
    with tempfile.TemporaryDirectory(prefix="dataauth-") as token_dir:
        with os.fdopen(
            os.open(
                os.path.join(token_dir, "token.tkn"), os.O_WRONLY | os.O_CREAT, 0o600
            ),
            "w",
        ) as token:
            token.write(str(idtoken))
        env = dict(os.environ)
        env["_CONDOR_SEC_TOKEN_DIRECTORY"] = token_dir
        env["_CONDOR_SEC_CLIENT_AUTHENTICATION_METHODS"] = "IDTOKENS"
        env["_CONDOR_SEC_CLIENT_AUTHENTICATION"] = "REQUIRED"
        env["_CONDOR_TOOL.SEC_TOKEN_DIRECTORY"] = token_dir
        env["_CONDOR_TOOL.SEC_CLIENT_AUTHENTICATION_METHODS"] = "IDTOKENS"
        env["_CONDOR_TOOL.SEC_CLIENT_AUTHENTICATION"] = "REQUIRED"
        proc = sp.run(
            cmd,
            stdout=sp.PIPE,
            stderr=sp.PIPE,
            encoding="latin-1",
            timeout=timeout,
            env=env,
        )
    return proc


def ping_with_idtoken(idtoken: str, method: str) -> t.Tuple[bool, str]:
    """
    Ping condor with a given IDTOKEN to see if it is valid.
    We fork out to condor_ping because we need to have a separate
    token location for each test.

    Args:
        idtoken: The contents of the IDTOKEN to use for auth, as a string
        method: The method to ping with, either "read" or "write"

    Returns:
        success (bool): True if the command was authenticated.
        remote_user_name (str): The username we tried to authenticate as.
            This might be set even if auth failed.
    """
    # In the future, we should look into multiprocessing or a
    # ProcessPoolExecutor along with the Python bindings.

    result = run_with_idtoken(
        ["condor_ping", method, "-af", "MyRemoteUsername"],
        idtoken=idtoken,
    )
    remote_user_name = result.stdout.strip().splitlines()[0] if result.stdout else ""
    success = result.returncode == 0 and "@" in remote_user_name
    return success, remote_user_name


def _get_uid_domain() -> t.Optional[str]:
    """Return HTCondor's configured UID_DOMAIN, or None when unavailable."""
    try:
        import htcondor2 as htcondor

        return htcondor.param.get("UID_DOMAIN", None) or None
    except (AttributeError, KeyError, ImportError):
        return None


def _is_user_path_allowed(request_uri: str, remote_user_name: str) -> bool:
    """Authorize a user's qualified path and, when applicable, its /files alias."""
    if any(
        is_uri_allowed(request_uri, f"{prefix}/{remote_user_name}")
        for prefix in PATH_PREFIXES
    ):
        return True

    uid_domain = _get_uid_domain()
    if not uid_domain:
        return False

    local_part, separator, domain = remote_user_name.rpartition("@")
    if (
        not separator
        or not local_part
        or local_part in {".", ".."}
        or any(char in local_part for char in ("/", "\\", ":", "\0"))
        or not domain
    ):
        return False
    configured_domain = uid_domain.lower().strip(".")
    remote_domain = domain.lower().strip(".")
    if not configured_domain or not (
        remote_domain == configured_domain
        or remote_domain.endswith("." + configured_domain)
    ):
        return False

    # uploadmover creates this alias only in /files, not in the staging tree.
    return is_uri_allowed(request_uri, f"/files/{local_part}")


def drop_privileges(username: str) -> None:
    """Drop root privileges to the given user, including supplementary groups."""
    if os.geteuid() != 0:
        return
    user = pwd.getpwnam(username)
    os.initgroups(user.pw_name, user.pw_gid)
    os.setgid(user.pw_gid)
    os.setuid(user.pw_uid)


class UnixDomainHTTPServer(ThreadingHTTPServer):
    """
    A ThreadingHTTPServer that listens on a Unix domain socket.

    server_address is the path to the socket file, which is created
    (replacing any stale socket from a previous run) on bind and
    removed on server_close.
    """

    address_family = socket.AF_UNIX

    def server_bind(self):
        """Bind to the socket path, replacing any stale socket file."""
        # TCPServer.server_bind() expects an (host, port) tuple and would
        # choke on AF_UNIX's getsockname(), so bind manually instead.
        try:
            os.unlink(str(self.server_address))
        except FileNotFoundError:
            pass
        self.socket.bind(self.server_address)
        os.chmod(str(self.server_address), SOCKET_MODE)

    def server_close(self):
        """Close the listening socket and remove its socket file."""
        super().server_close()
        try:
            os.unlink(str(self.server_address))
        except FileNotFoundError:
            pass


class AuthHandler(BaseHTTPRequestHandler):

    def address_string(self) -> str:
        """Return a display name for the client; AF_UNIX peers are unnamed."""
        if isinstance(self.client_address, tuple) and self.client_address:
            return str(self.client_address[0])
        return "unix"

    def send_response(
        self, code: int, message: t.Optional[str] = None, logprefix: str = ""
    ):
        """Send an HTTP response and record its status without logging credentials."""
        logger.info(
            "%sresponse status=%s reason=%s",
            logprefix + ": " if logprefix else "",
            code,
            message or "",
        )
        super().send_response(code, message)
        self.send_header(
            "X-Dataauth-Response", "{} - {}".format(code, message or "no details")
        )

    def get_token_from_headers(self) -> t.Tuple[str, int, str]:
        """
        Extract the token from the Authorization header or Cookie header.

        Returns:
            token (str): The extracted token, or an empty string if not found.
            status_code (int): The HTTP status code to return if there's an error.
            error_message (str): The error message to return if there's an error.
        """
        auth_string = str(self.headers.get("Authorization", ""))
        cookie = str(self.headers.get("Cookie", ""))
        try:
            cookie_obj = cookies.SimpleCookie()
            cookie_obj.load(cookie)
            maybe_token = cookie_obj.get("placement_token_token")
            token = maybe_token.value if maybe_token else ""
        except cookies.CookieError:
            token = ""

        if token:
            return token, 0, ""

        if not token:
            # If no token is found in the cookie, check the Authorization header.
            # XXX Should the Authorization header win?
            if not auth_string.startswith("Bearer "):
                return "", 401, "No token cookie and no Bearer in authorization header"

            token = auth_string[7:].strip()  # Remove "Bearer " prefix

        if not token:
            return "", 401, "No token provided in cookie or authorization header"

        return token, 0, ""

    def do_GET(self):
        original_uri = self.headers.get("X-Original-URI", "")
        original_method = self.headers.get("X-Original-Method", "")
        logprefix = "request client={} original_method={} uri={}".format(
            self.headers.get("X-Forwarded-For", self.address_string()),
            original_method,
            original_uri,
        )

        # CORS preflight requests never carry credentials (browsers strip Authorization
        # on OPTIONS), so this must be authorized before the token check below runs.
        # This is a defense-in-depth fallback: nginx is expected to short-circuit
        # OPTIONS before it ever reaches auth_request/dataauth.
        if original_method.upper() == "OPTIONS":
            self.send_response(200, "Preflight", logprefix)
            self.end_headers()
            return

        token, status_code, error_message = self.get_token_from_headers()
        if not token:
            self.send_response(status_code, error_message, logprefix)
            self.end_headers()
            return

        if not token_looks_valid(token):
            self.send_response(401, "Malformed token", logprefix)
            self.end_headers()
            return

        if original_method.upper() in {"GET", "HEAD"}:
            method = "read"
        elif original_method.upper() in {"POST", "PUT", "DELETE", "PATCH"}:
            method = "write"
        else:
            self.send_response(
                400, "Unsupported method %s" % original_method, logprefix
            )
            self.end_headers()
            return

        success, remote_user_name = ping_with_idtoken(token, method)

        if success:
            # Check that the normalized path is within the allowed directory.
            # Users browse /files/ and can read their own staged /files_upload/ paths.
            if not _is_user_path_allowed(original_uri, remote_user_name):
                self.send_response(
                    403,
                    "Access to this path (%r) denied for %r"
                    % (original_uri, remote_user_name),
                    logprefix,
                )
            else:
                self.send_response(200, "Accepted %r" % remote_user_name, logprefix)
        else:
            self.send_response(403, "Access denied", logprefix)

        self.end_headers()


def main(argv=None):
    """Run the authorization service with paths from the shared configuration."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument(
        "--user",
        default="nginx",
        metavar="USER",
        help="user to drop privileges to when running as root (default: %(default)s)",
    )
    parser.add_argument("socket_path", nargs="?")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as err:
        parser.error(f"cannot load configuration: {err}")

    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    logger.addHandler(
        logging.FileHandler(config.log_dir / "dataauth.log", encoding="utf-8")
    )
    logger.propagate = False
    socket_path = args.socket_path or str(config.data_dir / "dataauth.sock")
    logger.info("Starting dataauth server on socket %s", socket_path)
    try:
        drop_privileges(args.user)
    except (KeyError, OSError) as err:
        parser.error("cannot drop privileges to {!r}: {}".format(args.user, err))
    server = UnixDomainHTTPServer(socket_path, AuthHandler)  # type: ignore
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
