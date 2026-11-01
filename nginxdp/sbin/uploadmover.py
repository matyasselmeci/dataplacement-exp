#!/usr/bin/env python3
"""
Move uploaded data-placement files into the nginx-published directory.

The mapfile associates AP user IDs with local Unix accounts. The service uses
those accounts to set file ownership and grants the nginx group read access to
published files. It runs continuously by default, reloading the mapfile on each
poll, or processes the current uploads once with ``--oneshot``.

When upload and published roots resolve to the same directory, files remain in
place; their ownership changes without altering their file modes.

Files must remain in staging until all processing is complete. Moving a file
to the published directory is the final step because the browser treats its
disappearance from staging as the upload-complete signal.
"""

import argparse
import grp
import hashlib
import logging
import os
import pathlib
import pwd
import stat
import sys
import time
from typing import List, NamedTuple, Tuple, Union

from nginxdp_config import DEFAULT_CONFIG_PATH, DEFAULT_LOG_DIR, load_config

assert sys.version_info >= (3, 6), "Requires Python 3.6+"


DEFAULT_MAPFILE = "/etc/condor/user-mapfiles/dataplacement_mapfile"
DEFAULT_PERIOD = 5  # seconds
LOG_PATH = os.path.join(DEFAULT_LOG_DIR, "uploadmover.log")


Pathish = Union[os.PathLike, str]
logger = logging.getLogger("uploadmover")


def _get_uid_domain() -> Union[str, None]:
    """Return HTCondor's configured UID_DOMAIN, or None when it is unavailable."""
    try:
        import htcondor2 as htcondor  # type:ignore

        return htcondor.param.get("UID_DOMAIN", None) or None
    except (AttributeError, KeyError, ImportError):
        return None


def _qualify_ap_user_id(ap_user_id: str) -> str:
    """
    Check if an AP user ID is fully qualified (i.e., contains a domain)
    and, if not, qualify it with either UID_DOMAIN from the condor config
    or the system's domain name.

    Args:
        ap_user_id: AP user ID to qualify.

    Returns:
        The fully qualified AP user ID.
    """
    if "@" in ap_user_id:
        return ap_user_id
    # If no domain is present, we need to qualify the user ID
    uid_domain = _get_uid_domain()
    if not uid_domain:
        import socket

        uid_domain = socket.getfqdn()
    return f"{ap_user_id}@{uid_domain}"


def _read_uid_min(login_defs_path: Pathish = "/etc/login.defs") -> int:
    """
    Read the minimum UID for regular user accounts.

    For safety, we want to avoid creating or chowning files to system accounts.
    /etc/login.defs contains a UID_MIN setting that defines the minimum UID for
    regular user accounts. This function reads that setting and returns its value,
    falling back to 1000 if we can't read the setting.

    Args:
        login_defs_path: Path to the system login definitions file.

    Returns:
        The minimum UID for regular user accounts.
    """
    uid_min = 1000  # default fallback
    try:
        found = False
        with open(login_defs_path, encoding="utf-8") as login_defs:
            for raw_line in login_defs:
                line = raw_line.partition("#")[0].strip()
                fields = line.split()
                if fields and fields[0] == "UID_MIN":
                    try:
                        uid_min = int(fields[1])
                        found = True  # keep going - might be defined multiple times
                    except (IndexError, ValueError):
                        pass
            if not found:
                logger.info(
                    "Valid UID_MIN not found in %s; using default (1000)",
                    login_defs_path,
                )
    except OSError as err:
        logger.warning(
            "Unable to read %s (%s); using default (1000)",
            login_defs_path,
            err,
        )

    return uid_min


class UserMapping(NamedTuple):
    """
    Associate an AP user ID with a local Unix username.

    Attributes:
        ap_user_id: AP identity used as the user's upload and published
            directory name.
        username: Local Unix account that owns the user's files.
    """

    ap_user_id: str
    username: str

    @property
    def uid(self) -> int:
        """
        Return the UID of ``username``.

        Returns:
            The Unix user ID from the system account database.

        Raises:
            KeyError: If ``username`` is not a local Unix account.
        """
        return pwd.getpwnam(self.username).pw_uid


class Options(NamedTuple):
    """
    Command-line settings used by the upload mover.

    Attributes:
        mapfile: Path to a file that maps AP user IDs to Unix usernames.
        nginx_files_dir: Root directory for published files.
        nginx_upload_dir: Root directory for incoming uploads.
        period: Seconds between polling iterations in continuous mode.
        oneshot: Whether to process uploads once and exit.
        log_path: Path to a file that receives service logs.
    """

    mapfile: pathlib.Path
    nginx_files_dir: pathlib.Path
    nginx_upload_dir: pathlib.Path
    period: int
    oneshot: bool
    log_path: pathlib.Path = pathlib.Path(LOG_PATH)


def _read_dataplacement_mapfile(
    mapfile_path: Pathish,
) -> Tuple[List[UserMapping], int, str]:
    """
    Read a mapfile and return its accepted mappings and content metadata.

    Each nonblank, non-comment line must contain an AP user ID and a Unix
    username separated by whitespace. Leading and trailing whitespace is
    ignored, and a line is a comment when its first non-whitespace character
    is ``#``. The function skips malformed lines, unsafe AP user IDs, IDs
    already present in an accepted mapping, unknown Unix accounts, and
    accounts whose UID is below the system's configured ``UID_MIN``. It logs
    each rejected entry.

    Args:
        mapfile_path: Path to the mapfile.

    Returns:
        A tuple containing the accepted mappings, the count of nonblank,
        non-comment lines (including invalid entries), and the SHA-256
        hexadecimal digest of the original file bytes.

    Raises:
        OSError: If the mapfile cannot be read.
        UnicodeDecodeError: If the mapfile is not valid UTF-8.
    """
    content = pathlib.Path(mapfile_path).read_bytes()
    text = content.decode("utf-8")
    mappings = []
    seen_ids = set()
    entry_count = 0
    uid_min = _read_uid_min()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        entry_count += 1

        fields = line.split()
        if len(fields) != 2:
            logger.warning(
                "Ignoring malformed mapfile line %d: expected two fields",
                line_number,
            )
            continue

        ap_user_id, username = fields
        if not _is_safe_component(ap_user_id):
            logger.warning(
                "Ignoring mapfile line %d with unsafe AP user ID %r",
                line_number,
                ap_user_id,
            )
            continue
        if ap_user_id in seen_ids:
            logger.warning(
                "Ignoring duplicate AP user ID %r on mapfile line %d",
                ap_user_id,
                line_number,
            )
            continue

        mapping = UserMapping(_qualify_ap_user_id(ap_user_id), username)
        try:
            uid = mapping.uid
        except KeyError:
            logger.warning(
                "Ignoring mapfile line %d: Unix user %r does not exist",
                line_number,
                username,
            )
            continue
        if uid < uid_min:
            logger.warning(
                "Ignoring mapfile line %d: Unix user %r has UID below %d",
                line_number,
                username,
                uid_min,
            )
            continue

        seen_ids.add(ap_user_id)
        mappings.append(mapping)

    return mappings, entry_count, hashlib.sha256(content).hexdigest()


def read_dataplacement_mapfile(mapfile_path: Pathish) -> List[UserMapping]:
    """
    Read a mapfile and return its accepted AP user mappings.

    Parsing uses the same validation as ``_read_dataplacement_mapfile``; this
    function omits the entry count and content digest.

    Args:
        mapfile_path: Path to the mapfile.

    Returns:
        The mappings whose AP IDs and Unix accounts pass validation.

    Raises:
        OSError: If the mapfile cannot be read.
        UnicodeDecodeError: If the mapfile is not valid UTF-8.
    """
    mappings, _, _ = _read_dataplacement_mapfile(mapfile_path)
    return mappings


def _warn_on_empty_mapfile(
    mapfile_path: Pathish,
    mappings: List[UserMapping],
    entry_count: int,
    content_hash: str,
    last_seen_hash: Union[str, None],
) -> str:
    """
    Warn when a mapfile has no accepted mappings.

    To avoid excessive logging, the function only warns when the mapfile contents
    change (as determined by comparing ``content_hash`` to ``last_seen_hash``).

    Args:
        mapfile_path: Path used to identify the mapfile in the warning.
        mappings: Accepted mappings parsed from the file.
        entry_count: Number of nonblank, non-comment lines in the file.
        content_hash: SHA-256 digest identifying the current file contents.
        last_seen_hash: Digest from the previous check, or ``None`` if this is
            the first check.

    Returns:
        ``content_hash``, for use as the hash on the next check.
    """
    if content_hash == last_seen_hash:
        return content_hash
    if entry_count == 0:
        logger.warning("Mapfile %s contains no entries", mapfile_path)
    elif not mappings:
        logger.warning(
            "Mapfile %s contains entries, but all entries were filtered out as invalid",
            mapfile_path,
        )
    return content_hash


def _is_safe_component(value: str) -> bool:
    """
    Check whether a value can be used as one path component.

    The value must be nonempty, must not be ``.`` or ``..``, and must not
    contain a slash, backslash, colon, or NUL character.

    Args:
        value: String to validate.

    Returns:
        Whether the value meets the component restrictions.
    """
    return (
        bool(value)
        and value not in {".", ".."}
        and not any(char in value for char in ("/", "\\", ":", "\0"))
    )


def _require_within(path: pathlib.Path, root: pathlib.Path) -> pathlib.Path:
    """
    Resolve a path and reject it if it falls outside a configured root.

    The root must exist. The candidate may be missing, but existing symlinks
    are resolved before the containment check.

    Args:
        path: Candidate path to check.
        root: Existing root path that bounds the candidate.

    Returns:
        The resolved candidate path.

    Raises:
        OSError: If resolving the root or candidate fails.
        ValueError: If the resolved candidate is outside the resolved root.
    """
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as err:
        raise ValueError(f"Path {path} is outside {root}") from err
    return resolved_path


def _nginx_gid() -> int:
    """
    Return the system group ID for ``nginx``.

    Returns:
        The group ID used to assign ownership and access to published files.

    Raises:
        KeyError: If the ``nginx`` group is not present in the group database.
    """
    return grp.getgrnam("nginx").gr_gid


def _ensure_directory(
    directory: pathlib.Path, root: pathlib.Path, uid: int, gid: int
) -> None:
    """
    Create directories below ``root`` and set their owner and mode.

    The root itself is not changed. Each descendant directory is created if
    needed, then assigned ``uid`` and ``gid`` with mode ``0o770``. Existing
    symlinks and non-directory entries are rejected.

    Args:
        directory: Directory to create or repair.
        root: Existing root directory that must contain ``directory``.
        uid: Owner user ID for descendant directories.
        gid: Owner group ID for descendant directories.

    Raises:
        OSError: If the root cannot be resolved, a descendant is not a
            directory, or a filesystem operation fails.
        ValueError: If ``directory`` is not lexically below ``root``.
    """
    root_real = root.resolve(strict=True)
    root_lexical = root.absolute()
    directory_lexical = directory.absolute()
    try:
        relative = directory_lexical.relative_to(root_lexical)
    except ValueError as err:
        raise ValueError(f"Path {directory} is outside {root}") from err

    current = root_real
    for component in relative.parts:
        current = current / component
        try:
            current.mkdir(mode=0o770)
        except FileExistsError:
            mode = current.lstat().st_mode
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise OSError(f"Expected a directory at {current}")
        os.chown(current, uid, gid, follow_symlinks=False)
        os.chmod(current, 0o770, follow_symlinks=False)


def ensure_dest_dir_exists(mapping: UserMapping, opts: Options):
    """
    Create or repair the published directory for one mapped user.

    The directory is named after the AP user ID under ``opts.nginx_files_dir``.
    It is owned by the mapped Unix account and the ``nginx`` group, with
    owner/group read and write permissions and execute permission.

    Args:
        mapping: AP user ID and Unix username for the directory owner.
        opts: Service settings containing the published-files root.

    Raises:
        KeyError: If the mapped Unix account or ``nginx`` group is unknown.
        OSError: If the directory cannot be created or updated.
        ValueError: If the AP user ID is unsafe or the destination is outside
            the configured root.
    """
    if not _is_safe_component(mapping.ap_user_id):
        raise ValueError(f"Unsafe AP user ID: {mapping.ap_user_id!r}")
    dest_dir = opts.nginx_files_dir / mapping.ap_user_id
    _ensure_directory(dest_dir, opts.nginx_files_dir, mapping.uid, _nginx_gid())


def ensure_unqualified_symlink(
    mapping: UserMapping, uid_domain: Union[str, None], opts: Options
) -> None:
    """Create the local-part alias for a mapped ID in the configured UID domain."""
    if not uid_domain:
        return
    local_part, separator, domain = mapping.ap_user_id.partition("@")
    if not separator or domain != uid_domain or not _is_safe_component(local_part):
        return

    ensure_dest_dir_exists(mapping, opts)
    alias_path = opts.nginx_files_dir / local_part
    try:
        alias_path.symlink_to(mapping.ap_user_id)
    except FileExistsError:
        if alias_path.is_symlink() and os.readlink(alias_path) == mapping.ap_user_id:
            return
        raise OSError(f"Cannot create AP user alias at existing path {alias_path}")


def move_and_chown_file(
    src_path: Pathish, dst_path: Pathish, owner: Union[str, int], opts: Options
):
    """
    Set a file's ownership and publish it at the destination.

    Both configured roots must contain their respective paths. The source and
    any existing destination must be regular files, not symlinks or other
    filesystem entries. Destination parent directories are created with
    ``owner`` and the ``nginx`` group, using mode ``0o770``.

    The source is always assigned ``owner`` and the ``nginx`` group. If the
    upload and published roots resolve to different directories, the function
    adds group-read permission and replaces the destination with the source
    using ``os.replace``. If the roots are the same, the source stays in place
    and its mode is unchanged.

    Args:
        src_path: Upload file below ``opts.nginx_upload_dir``.
        dst_path: Published-file path below ``opts.nginx_files_dir``.
        owner: Unix username or UID that should own the file and directories.
        opts: Service settings containing both configured roots.

    Raises:
        KeyError: If ``owner`` or the ``nginx`` group is unknown.
        OSError: If either file is not regular, a filesystem operation fails,
            or a path cannot be resolved.
        ValueError: If either path escapes its configured root or the
            destination contains an unsafe component.
    """
    src = pathlib.Path(src_path)
    dst = pathlib.Path(dst_path)
    _require_within(src, opts.nginx_upload_dir)
    _require_within(dst.parent, opts.nginx_files_dir)

    # Uploads are untrusted filesystem entries; do not publish symlinks or
    # special files, and do not allow a destination symlink to redirect writes.
    if not stat.S_ISREG(src.lstat().st_mode):
        raise OSError(f"Upload is not a regular file: {src}")
    if os.path.lexists(dst) and not stat.S_ISREG(dst.lstat().st_mode):
        raise OSError(f"Destination is not a regular file: {dst}")

    uid = (
        pwd.getpwuid(owner).pw_uid
        if isinstance(owner, int)
        else pwd.getpwnam(owner).pw_uid
    )
    gid = _nginx_gid()
    dest_root = opts.nginx_files_dir.resolve(strict=True)
    dest_relative = dst.relative_to(opts.nginx_files_dir)
    if not dest_relative.parts or any(
        not _is_safe_component(component) for component in dest_relative.parts
    ):
        raise ValueError(f"Unsafe destination path: {dst}")

    user_dir = dest_root / dest_relative.parts[0]
    _ensure_directory(user_dir, dest_root, uid, gid)
    parent = user_dir
    for component in dest_relative.parts[1:-1]:
        if not _is_safe_component(component):
            raise ValueError(f"Unsafe destination path: {dst}")
        parent = parent / component
        _ensure_directory(parent, user_dir, uid, gid)

    same_root = opts.nginx_files_dir.resolve() == opts.nginx_upload_dir.resolve()
    os.chown(src, uid, gid, follow_symlinks=False)
    if not same_root:
        # Published files need nginx group-read access after they are moved.
        mode = (stat.S_IMODE(src.lstat().st_mode) & 0o777) | stat.S_IRGRP
        os.chmod(src, mode, follow_symlinks=False)
        dst = parent / dst.name
        os.replace(src, dst)


def get_options(argv) -> Options:
    """
    Parse command-line arguments into service settings.

    Args:
        argv: Argument strings passed to the command-line parser, excluding
            the program name. ``None`` parses the process command line.

    Returns:
        An ``Options`` tuple with filesystem arguments converted to
        ``pathlib.Path`` objects.

    Raises:
        SystemExit: If an argument is invalid or ``--period`` is not positive.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--mapfile", default=DEFAULT_MAPFILE)
    parser.add_argument("--nginx-files-dir")
    parser.add_argument("--nginx-upload-dir")
    parser.add_argument(
        "--period",
        type=int,
        default=None,
        help="seconds between polls (default: uploadmover_period from the config)",
    )
    parser.add_argument("--oneshot", action="store_true")
    parser.add_argument(
        "--log-file",
        "--log-path",
        dest="log_path",
        default=None,
        help="write logs to this file in addition to stderr",
    )
    args = parser.parse_args(argv)
    if args.period is not None and args.period <= 0:
        parser.error("--period must be a positive number of seconds")
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as err:
        parser.error(f"cannot load configuration: {err}")
    opts = Options(
        mapfile=pathlib.Path(args.mapfile),
        nginx_files_dir=pathlib.Path(args.nginx_files_dir or config.data_dir / "files"),
        nginx_upload_dir=pathlib.Path(
            args.nginx_upload_dir or config.data_dir / "files_upload"
        ),
        period=args.period or config.uploadmover_period,
        oneshot=args.oneshot,
        log_path=pathlib.Path(args.log_path or config.log_dir / "uploadmover.log"),
    )
    return opts


def move_uploaded_files(
    mappings: List[UserMapping], opts: Options
) -> Tuple[List[str], List[str]]:
    """
    Process upload files for the supplied user mappings.

    For each safe AP user ID, the function scans its upload directory
    recursively. It moves regular files to the published root when the roots
    differ, or changes ownership in place when they resolve to the same
    directory. Missing user upload directories are skipped. Unsafe mappings,
    invalid upload directories, and failed files are logged. Failed files and
    skipped symlinked subdirectories encountered during the scan appear in
    the returned failure list.

    Args:
        mappings: AP user ID to Unix account mappings to process.
        opts: Service settings containing upload and published roots.

    Returns:
        A pair of lists containing successful and failed file paths,
        respectively. Paths are relative to the published root and use POSIX
        separators. Unsafe mappings and upload-directory errors are logged but
        are not included in either list.
    """
    successes = []
    failures = []
    uid_domain = _get_uid_domain()

    for mapping in mappings:
        if not _is_safe_component(mapping.ap_user_id):
            logger.error("Skipping unsafe AP user ID %r", mapping.ap_user_id)
            continue

        try:
            ensure_unqualified_symlink(mapping, uid_domain, opts)
        except (OSError, ValueError) as err:
            logger.error(
                "Cannot create unqualified alias for %s: %s", mapping.ap_user_id, err
            )

        user_upload_dir = opts.nginx_upload_dir / mapping.ap_user_id
        try:
            if user_upload_dir.is_symlink():
                raise OSError(f"Upload path is a symlink: {user_upload_dir}")
            user_upload_real = _require_within(user_upload_dir, opts.nginx_upload_dir)
            if not user_upload_real.exists():
                continue
            if not stat.S_ISDIR(user_upload_real.lstat().st_mode):
                raise OSError(f"Upload path is not a directory: {user_upload_dir}")
        except (OSError, ValueError) as err:
            logger.error("Cannot scan uploads for %s: %s", mapping.ap_user_id, err)
            continue

        for current_dir, dirnames, filenames in os.walk(user_upload_real):
            current_path = pathlib.Path(current_dir)
            for dirname in list(dirnames):
                child = current_path / dirname
                if child.is_symlink():
                    dirnames.remove(dirname)
                    relative = child.relative_to(user_upload_real)
                    failures.append(
                        (pathlib.Path(mapping.ap_user_id) / relative).as_posix()
                    )

            for filename in filenames:
                src = current_path / filename
                relative = src.relative_to(user_upload_real)
                relative_dest = pathlib.Path(mapping.ap_user_id) / relative
                dst = opts.nginx_files_dir / relative_dest
                try:
                    ensure_dest_dir_exists(mapping, opts)
                    move_and_chown_file(src, dst, mapping.username, opts)
                except (OSError, ValueError) as err:
                    logger.error("Failed to process upload %s: %s", src, err)
                    failures.append(relative_dest.as_posix())
                else:
                    successes.append(relative_dest.as_posix())

    return successes, failures


def _configure_logging(log_path: Pathish = LOG_PATH) -> None:
    """
    Configure upload-mover logging to stderr and a log file.

    Existing handlers on the upload-mover logger are removed and closed. The
    logger is set to ``INFO`` and does not propagate records to parent loggers.

    Args:
        log_path: File to receive log records in addition to stderr.

    Raises:
        OSError: If the log file cannot be opened.
    """
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler())
    logger.addHandler(logging.FileHandler(log_path, encoding="utf-8"))
    logger.propagate = False


def main():
    """
    Run one upload pass or poll continuously, according to command options.

    Continuous mode reloads the mapfile before each pass. A mapfile read error
    on the first pass is re-raised; later read or upload-processing errors are
    logged and retried after a longer delay. ``--oneshot`` processes the
    current mappings once and returns.

    Raises:
        OSError: If the mapfile cannot be read during the first continuous
            iteration.
        SystemExit: If command-line arguments are invalid.
    """
    opts = get_options(sys.argv[1:])
    _configure_logging(opts.log_path)
    logger.info("Starting upload mover")
    action = (
        "chowned"
        if opts.nginx_files_dir.resolve() == opts.nginx_upload_dir.resolve()
        else "moved"
    )
    if opts.oneshot:
        mappings, entry_count, content_hash = _read_dataplacement_mapfile(opts.mapfile)
        _warn_on_empty_mapfile(opts.mapfile, mappings, entry_count, content_hash, None)
        successes, failures = move_uploaded_files(mappings, opts)
        if successes:
            logger.info("%d files %s", len(successes), action)
            logger.debug("Files %s: %r", action, successes)
        if failures:
            logger.warning("%d files failed to process", len(failures))
            logger.debug("Files failed to process: %r", failures)
    else:
        first = True
        last_mapfile_hash = None
        while True:
            try:
                mappings, entry_count, content_hash = _read_dataplacement_mapfile(
                    opts.mapfile
                )
            except OSError as err:
                if first:
                    # If we can't read the mapfile right off the bat, exit.
                    logger.error("Error reading mapfile: %s", err)
                    raise
                else:
                    # If the mapfile disappears mid-loop, warn, but try again
                    # later.
                    logger.exception("Error reading mapfile: %s", err)
                    time.sleep(opts.period * 2)
                    continue
            first = False
            last_mapfile_hash = _warn_on_empty_mapfile(
                opts.mapfile,
                mappings,
                entry_count,
                content_hash,
                last_mapfile_hash,
            )
            try:
                successes, failures = move_uploaded_files(mappings, opts)
                if len(successes) > 0:
                    logger.info("%d files %s", len(successes), action)
                    logger.debug("Files %s: %r", action, successes)
                if len(failures) > 0:
                    logger.warning("%d files failed to process", len(failures))
                    logger.debug("Files failed to process: %r", failures)
                time.sleep(opts.period)
            except KeyboardInterrupt:
                print("Interrupt received, exiting", file=sys.stderr)
                sys.exit(0)
            except OSError as err:
                logger.exception("Error processing uploads: %s", err)
                time.sleep(opts.period * 2)
                continue


if __name__ == "__main__":
    main()
