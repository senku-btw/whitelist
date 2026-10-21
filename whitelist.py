"""Pi-hole automated whitelist and group management utility."""

import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

# --- Production Constants ---
DEFAULT_GROUP_ID = 0
DOMAIN_TYPE_EXACT = 0
DOMAIN_TYPE_REGEX = 2
DOMAIN_TYPE_WILDCARD = 3
ADLIST_TYPE = 1

IMMUTABLE_CATEGORIES: FrozenSet[str] = frozenset()
GROUP_IMMUTABLES = frozenset({"healthcheck", "hosts"})

# Strict allowlists for SQL identifiers to prevent injection via formatting
ALLOWED_TABLES = frozenset(
    {"domainlist", "domainlist_by_group", "adlist", "adlist_by_group", "group"}
)
ALLOWED_COLUMNS = frozenset(
    {"id", "domainlist_id", "adlist_id", "group_id", "domain", "type", "comment"}
)

# --- SQL Queries ---
SQL_GET_DEFAULT_ENTRIES = """
    SELECT d.domain
    FROM domainlist d
    JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
    JOIN "group" g ON dg.group_id = g.id
    WHERE d.type = ?
    AND (d.comment IS NULL OR d.comment = '')
    AND g.name = 'Default'
"""

SQL_GET_CATEGORIZED_DOMAINS = """
    SELECT domain, comment FROM domainlist
    WHERE type = ? AND comment IS NOT NULL AND comment != ''
    AND comment NOT IN ('healthcheck', 'healtcheck', 'hosts', 'host', 'Added from Query Log')
"""

SQL_GET_STANDARD_DOMAINS = """
    SELECT id, comment FROM domainlist
    WHERE comment IS NOT NULL AND comment != ''
    AND comment != 'Added from Query Log'
    AND (comment NOT IN ('healthcheck', 'healtcheck', 'hosts', 'host') OR type IN (?, ?))
"""

SQL_GET_CLIENT_BACKUPS = """
    SELECT cbg.client_id, g.name
    FROM client_by_group cbg
    JOIN "group" g ON cbg.group_id = g.id
    WHERE g.id != ?
"""

# --- Production Logging Setup ---
logger = logging.getLogger("PiholeWhitelistManager")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)


# --- Configuration ---
@dataclass(frozen=True)
class AppConfig:
    """Application configuration container for paths and timeouts."""

    db_path: Path
    repo_dir: Path
    whitelist_txt_path: Path
    whitelists_dir: Path
    subprocess_timeout: int = 30
    db_timeout: float = 10.0

    @classmethod
    def load(cls) -> "AppConfig":
        """Load configuration from environment variables and check paths securely."""
        default_db_path = os.getenv(
            "PIHOLE_DB_PATH",
            "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db",
        )
        db_path = Path(default_db_path).resolve()
        repo_dir = Path(__file__).resolve().parent

        if not db_path.is_file():
            raise FileNotFoundError(f"Pi-hole database missing: {db_path}")
        if not repo_dir.is_dir():
            raise NotADirectoryError(f"Repository directory missing: {repo_dir}")

        return cls(
            db_path=db_path,
            repo_dir=repo_dir,
            whitelist_txt_path=repo_dir / "whitelist.txt",
            whitelists_dir=repo_dir / "whitelists",
        )


@dataclass(frozen=True)
class GroupAssignmentSpec:
    """Specification for assigning entries to a specific group."""

    table: str
    link_table: str
    fk_col: str
    comments: Tuple[str, ...]
    group_id: Optional[int]
    type_cond: str

    def __post_init__(self) -> None:
        """Validate SQL identifiers to ensure secure execution."""
        if self.table not in ALLOWED_TABLES or self.link_table not in ALLOWED_TABLES:
            raise ValueError(f"Unauthorized table name in spec: {self.table}, {self.link_table}")
        if self.fk_col not in ALLOWED_COLUMNS:
            raise ValueError(f"Unauthorized column name in spec: {self.fk_col}")


# --- Core Utilities ---

def sanitize_domain(domain: str) -> str:
    """Sanitize and normalize a domain string securely."""
    if not isinstance(domain, str):
        raise TypeError(f"Expected string for domain, got {type(domain).__name__}")
    cleaned = domain.strip().lower()
    if not re.match(r"^[a-z0-9_.-]+$", cleaned):
        raise ValueError(f"Invalid characters detected in domain: {cleaned}")
    return cleaned


def parse_comment_categories(comment: Optional[str]) -> List[str]:
    """Parse categories out of a domain comment string safely."""
    if not comment or not isinstance(comment, str):
        return []
    cleaned_comment = re.sub(r"\{.*?\}", "", comment)
    return [c.strip() for c in cleaned_comment.split("/") if c.strip()]


def format_filename(category: str, base_dir: Path) -> Path:
    """Format category name into a safe filename protected against path traversal."""
    if not category:
        raise ValueError("Category name cannot be empty")
    safe_chars = "".join(c for c in category if c.isalnum() or c in (" ", "_", "-")).strip()
    safe_name = re.sub(r"\s+", "_", safe_chars) + ".txt"

    target_path = (base_dir / safe_name).resolve()
    if not target_path.is_relative_to(base_dir.resolve()):
        raise SecurityError(f"Path traversal attempt detected: {category}")
    return target_path


class SecurityError(Exception):
    """Raised when a security constraint or boundary is violated."""


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    capture_output: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Execute a system command securely with strict timeouts."""
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Command timed out after %ds: %s", timeout, " ".join(cmd))
        raise RuntimeError(f"Command timeout: {' '.join(cmd)}") from exc
    except subprocess.CalledProcessError as exc:
        err_msg = exc.stderr.strip() if exc.stderr else str(exc)
        logger.error("Command failed (%s): %s", " ".join(cmd), err_msg)
        raise RuntimeError(f"Command execution failed: {err_msg}") from exc


def write_atomic(filepath: Path, lines: Iterable[str]) -> None:
    """Write data to a temp file and replace target atomically with correct permissions."""
    filepath.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            dir=filepath.parent,
            delete=False,
            encoding="utf-8",
        ) as f:
            tmp_path = Path(f.name)
            for line in lines:
                f.write(f"{line}\n")
            f.flush()
            os.fsync(f.fileno())

        tmp_path.chmod(0o644)
        tmp_path.replace(filepath)
    except Exception as exc:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
        raise IOError(f"Atomic write failed for {filepath}: {exc}") from exc


# --- Database Interactions ---

def execute_read(cfg: AppConfig, query: str, params: Tuple = ()) -> List[Tuple]:
    """Execute a read-only SQL query against the Pi-hole database safely."""
    try:
        db_uri = f"file:{cfg.db_path}?mode=ro"
        with sqlite3.connect(db_uri, uri=True, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Database read failure: {exc}") from exc


# --- Business Logic ---

def process_step1(cfg: AppConfig) -> None:
    """Copy default DB entries into whitelist.txt without removing them from the database."""
    db_entries_raw = execute_read(cfg, SQL_GET_DEFAULT_ENTRIES, (DOMAIN_TYPE_EXACT,))
    db_entries = frozenset(sanitize_domain(row[0]) for row in db_entries_raw)

    if not db_entries:
        logger.info("Step 1 Complete: No default DB entries require copying.")
        return

    txt_entries: FrozenSet[str] = frozenset()
    if cfg.whitelist_txt_path.exists():
        try:
            with open(cfg.whitelist_txt_path, "r", encoding="utf-8") as file_obj:
                txt_entries = frozenset(
                    sanitize_domain(line) for line in file_obj if line.strip()
                )
        except IOError as exc:
            raise RuntimeError(f"Failed to read existing whitelist.txt: {exc}") from exc

    combined_entries = sorted(list(db_entries | txt_entries))
    write_atomic(cfg.whitelist_txt_path, combined_entries)

    logger.info("Step 1 Complete: Extracted and copied %d entries.", len(db_entries))


def extract_categorized_whitelists(cfg: AppConfig) -> Dict[str, FrozenSet[str]]:
    """Parse DB and cluster domains into categories securely."""
    rows = execute_read(cfg, SQL_GET_CATEGORIZED_DOMAINS, (DOMAIN_TYPE_EXACT,))

    temp_dict: Dict[str, Set[str]] = {}
    for domain, comment in rows:
        categories = parse_comment_categories(comment)
        sanitized_dom = sanitize_domain(domain)
        for cat in categories:
            temp_dict.setdefault(cat, set()).add(sanitized_dom)

    return {
        cat: frozenset(domains)
        for cat, domains in temp_dict.items()
        if len(domains) >= 2 or cat.lower() in IMMUTABLE_CATEGORIES
    }


def write_category_files(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Write generated categories to physical category files with path protection."""
    cfg.whitelists_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    for existing_file in cfg.whitelists_dir.glob("*.txt"):
        if existing_file.stem.lower() in IMMUTABLE_CATEGORIES:
            continue
        existing_file.unlink()

    for category, domains in categories.items():
        if category.lower() in IMMUTABLE_CATEGORIES:
            logger.info("Skipping write/overwrite for immutable file: %s.txt", category.lower())
            continue
        file_path = format_filename(category, cfg.whitelists_dir)
        write_atomic(file_path, sorted(list(domains)))


def _assign_exclusive_group(cursor: sqlite3.Cursor, spec: GroupAssignmentSpec) -> None:
    """Exclusively assign domains/adlists matching comments to a group securely."""
    if spec.group_id is None:
        return
    placeholders = " OR ".join(["comment = ?"] * len(spec.comments))
    query = f"SELECT id FROM {spec.table} WHERE ({placeholders}) AND {spec.type_cond}"
    cursor.execute(query, spec.comments)
    ids = [row[0] for row in cursor.fetchall()]
    if ids:
        cursor.executemany(
            f"DELETE FROM {spec.link_table} WHERE {spec.fk_col} = ?",
            [(item_id,) for item_id in ids],
        )
        cursor.executemany(
            f"INSERT INTO {spec.link_table} ({spec.fk_col}, group_id) VALUES (?, ?)",
            [(item_id, spec.group_id) for item_id in ids],
        )


def _recreate_groups(
    cursor: sqlite3.Cursor, categories: Dict[str, FrozenSet[str]]
) -> Dict[str, int]:
    """Rebuild non-default group definitions safely and return group map."""
    cursor.execute('SELECT id FROM "group" WHERE id = ?', (DEFAULT_GROUP_ID,))
    if cursor.fetchone() is None:
        raise RuntimeError(f"Integrity Error: Default group (id={DEFAULT_GROUP_ID}) missing.")

    cursor.execute("DELETE FROM client_by_group WHERE group_id != ?", (DEFAULT_GROUP_ID,))
    cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != ?", (DEFAULT_GROUP_ID,))
    cursor.execute('DELETE FROM "group" WHERE id != ?', (DEFAULT_GROUP_ID,))

    sorted_categories = sorted(categories.keys())
    for req_cat in GROUP_IMMUTABLES:
        if req_cat not in sorted_categories:
            sorted_categories.append(req_cat)

    cursor.executemany(
        'INSERT INTO "group" (name, description) VALUES (?, ?)',
        [(cat, cat) for cat in sorted_categories],
    )

    cursor.execute('SELECT id, name FROM "group" WHERE id != ?', (DEFAULT_GROUP_ID,))
    return {name: gid for gid, name in cursor.fetchall()}


def _assign_standard_domains(cursor: sqlite3.Cursor, group_map: Dict[str, int]) -> None:
    """Link non-exclusive domainlist entries exclusively to comment categories."""
    cursor.execute(SQL_GET_STANDARD_DOMAINS, (DOMAIN_TYPE_REGEX, DOMAIN_TYPE_WILDCARD))

    domain_ids_to_clear: Set[int] = set()
    domain_group_links: List[Tuple[int, int]] = []

    for d_id, comment in cursor.fetchall():
        matched_gids = [
            group_map[tag]
            for tag in parse_comment_categories(comment)
            if tag in group_map
        ]
        if matched_gids:
            domain_ids_to_clear.add(d_id)
            for gid in matched_gids:
                domain_group_links.append((d_id, gid))

    if domain_ids_to_clear:
        cursor.executemany(
            "DELETE FROM domainlist_by_group WHERE domainlist_id = ?",
            [(d_id,) for d_id in domain_ids_to_clear],
        )

    if domain_group_links:
        cursor.executemany(
            "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
            domain_group_links,
        )


def _assign_regex_allow_groups(cursor: sqlite3.Cursor, group_map: Dict[str, int]) -> None:
    """Enforce exclusive group assignment for regex allow lists securely."""
    cursor.execute("SELECT id, comment FROM domainlist WHERE type = ?", (DOMAIN_TYPE_REGEX,))
    regex_entries = cursor.fetchall()

    for d_id, comment in regex_entries:
        matched_gids = set()
        if comment:
            tags = parse_comment_categories(comment)
            for tag in tags:
                if tag in group_map:
                    matched_gids.add(group_map[tag])

        cursor.execute("DELETE FROM domainlist_by_group WHERE domainlist_id = ?", (d_id,))

        if matched_gids:
            cursor.executemany(
                "INSERT INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
                [(d_id, gid) for gid in matched_gids],
            )
        else:
            cursor.execute(
                "INSERT INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
                (d_id, DEFAULT_GROUP_ID),
            )


# pylint: disable=too-many-locals
def rebuild_db_groups(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Rebuild Pi-hole DB groups safely within an atomic transaction."""
    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            with conn:
                cursor.execute(
                    "UPDATE domainlist SET comment = 'healthcheck' WHERE comment = 'healtcheck'"
                )
                cursor.execute(
                    "UPDATE adlist SET comment = 'healthcheck' WHERE comment = 'healtcheck'"
                )
                cursor.execute(
                    "UPDATE domainlist SET comment = 'hosts' WHERE comment = 'host'"
                )
                cursor.execute(
                    "UPDATE adlist SET comment = 'hosts' WHERE comment = 'host'"
                )

                cursor.execute(SQL_GET_CLIENT_BACKUPS, (DEFAULT_GROUP_ID,))
                client_backups = cursor.fetchall()

                group_map = _recreate_groups(cursor, categories)
                group_map["Default"] = DEFAULT_GROUP_ID

                _assign_standard_domains(cursor, group_map)
                _assign_regex_allow_groups(cursor, group_map)

                hc_gid = group_map.get("healthcheck")
                hosts_gid = group_map.get("hosts")

                specs = [
                    GroupAssignmentSpec(
                        table="domainlist",
                        link_table="domainlist_by_group",
                        fk_col="domainlist_id",
                        comments=("healthcheck",),
                        group_id=hc_gid,
                        type_cond=f"type IN ({DOMAIN_TYPE_EXACT}, {DOMAIN_TYPE_REGEX})",
                    ),
                    GroupAssignmentSpec(
                        table="domainlist",
                        link_table="domainlist_by_group",
                        fk_col="domainlist_id",
                        comments=("hosts",),
                        group_id=hosts_gid,
                        type_cond=f"type IN ({DOMAIN_TYPE_EXACT}, {DOMAIN_TYPE_REGEX})",
                    ),
                    GroupAssignmentSpec(
                        table="adlist",
                        link_table="adlist_by_group",
                        fk_col="adlist_id",
                        comments=("healthcheck",),
                        group_id=hc_gid,
                        type_cond=f"type = {ADLIST_TYPE}",
                    ),
                    GroupAssignmentSpec(
                        table="adlist",
                        link_table="adlist_by_group",
                        fk_col="adlist_id",
                        comments=("hosts",),
                        group_id=hosts_gid,
                        type_cond=f"type = {ADLIST_TYPE}",
                    ),
                ]

                for spec in specs:
                    _assign_exclusive_group(cursor, spec)

                client_group_links = [
                    (client_id, group_map[group_name])
                    for client_id, group_name in client_backups
                    if group_name in group_map
                ]

                if client_group_links:
                    cursor.executemany(
                        "INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?, ?)",
                        client_group_links,
                    )

        logger.info(
            "Steps 2 & 3 Complete: Successfully rebuilt %d database groups.",
            len(categories),
        )
    except sqlite3.Error as exc:
        raise RuntimeError(f"Database transaction failed during group rebuild: {exc}") from exc


def export_regex_allowlist(cfg: AppConfig) -> None:
    """Export regex allow entries securely, filtering sensitive groups."""
    query = """
        SELECT DISTINCT d.domain, d.comment, g.name
        FROM domainlist d
        LEFT JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
        LEFT JOIN "group" g ON dg.group_id = g.id
        WHERE d.type = ?
    """
    rows = execute_read(cfg, query, (DOMAIN_TYPE_REGEX,))
    regex_dict: Dict[str, Set[str]] = {}

    for domain, comment, group_name in rows:
        tags = parse_comment_categories(comment)
        tag_match = any(t.lower() in ("healthcheck", "hosts") for t in tags)
        group_match = group_name and group_name.lower() in ("healthcheck", "hosts")

        if tag_match or group_match:
            continue

        sanitized_pattern = "".join(
            char for char in domain if char.isprintable() and not char.isspace()
        )
        safe_comment = comment.strip() if comment and comment.strip() else "Default"

        regex_dict.setdefault(safe_comment, set()).add(sanitized_pattern)

    output_lines = []
    for comment_group, patterns in sorted(regex_dict.items()):
        for pattern in sorted(patterns):
            output_lines.extend([f"{pattern} -- {comment_group}", ""])

    regex_dir = (cfg.repo_dir / "regex").resolve()
    if not regex_dir.is_relative_to(cfg.repo_dir.resolve()):
        raise SecurityError("Invalid regex export directory path.")

    regex_dir.mkdir(parents=True, exist_ok=True)
    allowlist_path = regex_dir / "allowlist.txt"
    write_atomic(allowlist_path, output_lines)
    logger.info("Exported filtered regex allowlist to %s", allowlist_path)


def push_to_github(cfg: AppConfig) -> None:
    """Commit and push configuration changes safely."""
    git_dir = (cfg.repo_dir / ".git").resolve()
    if not git_dir.is_dir():
        raise RuntimeError(f"Not a valid Git repository: {cfg.repo_dir}")

    run_command(
        [
            "git",
            "add",
            str(cfg.whitelist_txt_path.name),
            str(cfg.whitelists_dir.name),
            "regex",
        ],
        cwd=cfg.repo_dir,
        timeout=cfg.subprocess_timeout,
    )

    status = run_command(
        ["git", "status", "--porcelain"],
        cwd=cfg.repo_dir,
        capture_output=True,
        timeout=cfg.subprocess_timeout,
    )
    if not status.stdout.strip():
        logger.info("Step 4 Complete: No modifications. Skipping Git push.")
        return

    commit_msg = os.urandom(4).hex()
    run_command(
        ["git", "commit", "-m", commit_msg],
        cwd=cfg.repo_dir,
        timeout=cfg.subprocess_timeout,
    )

    try:
        subprocess.run(
            ["git", "push"],
            cwd=cfg.repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=cfg.subprocess_timeout,
        )
        logger.info("Step 4 Complete: Commit '%s' pushed successfully.", commit_msg)
    except Exception as exc:
        logger.error("Failed to execute git push: %s", exc, exc_info=True)
        raise RuntimeError(f"Git push failed: {exc}") from exc


# --- Main Execution Control ---

def main() -> None:
    """Run the primary Pi-hole whitelist automation routine securely."""
    # pylint: disable=broad-exception-caught
    logger.info("Initializing Pi-hole Whitelist Automation...")
    try:
        cfg = AppConfig.load()

        process_step1(cfg)

        categories = extract_categorized_whitelists(cfg)
        if not categories:
            logger.info("No categorizable whitelists found. Skipping rebuild.")
            export_regex_allowlist(cfg)
            push_to_github(cfg)
            return

        write_category_files(cfg, categories)
        rebuild_db_groups(cfg, categories)

        run_command(
            ["docker", "exec", "pihole", "pihole", "reloadlists"],
            timeout=cfg.subprocess_timeout,
        )

        export_regex_allowlist(cfg)
        push_to_github(cfg)
        logger.info("Automation sequence completed successfully.")

    except Exception as exc:
        logger.critical("FATAL ERROR: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
