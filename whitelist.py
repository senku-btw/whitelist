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

# --- Production Logging Setup ---
logger = logging.getLogger("PiholeWhitelistManager")
logger.setLevel(logging.INFO)
HANDLER = logging.StreamHandler(sys.stdout)
FORMATTER = logging.Formatter(
    "%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
HANDLER.setFormatter(FORMATTER)
if not logger.handlers:
    logger.addHandler(HANDLER)


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
        """Load configuration from environment variables and check paths."""
        default_db_path = os.getenv(
            "PIHOLE_DB_PATH",
            (
                "/mnt/dietpi_userdata/docker/primary-stack/"
                "pihole/etc-pihole/gravity.db"
            ),
        )
        db_path = Path(default_db_path)
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


# --- Core Utilities ---


def sanitize_domain(domain: str) -> str:
    """Sanitize and normalize a domain string."""
    if not isinstance(domain, str):
        raise TypeError(f"Expected string for domain, got {type(domain).__name__}")
    return domain.strip().lower()


def parse_comment_categories(comment: Optional[str]) -> List[str]:
    """Parse categories out of a domain comment string."""
    if not comment or not isinstance(comment, str):
        return []
    cleaned_comment = re.sub(r"\{.*?\}", "", comment)
    return [c.strip() for c in cleaned_comment.split("/") if c.strip()]


def format_filename(category: str) -> str:
    """Format category name into a safe filename."""
    if not category:
        raise ValueError("Category name cannot be empty")
    safe_chars = "".join(
        c for c in category if c.isalnum() or c in (" ", "_", "-")
    ).strip()
    return re.sub(r"\s+", "_", safe_chars)


def run_command(
    cmd: List[str],
    cwd: Optional[Path] = None,
    capture_output: bool = True,
    timeout: int = 30,
) -> subprocess.CompletedProcess:
    """Execute a system command securely with timeouts."""
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
    """Write data to a temp file and replace target atomically."""
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

        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, filepath)
    except Exception as exc:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
        raise IOError(f"Atomic write failed for {filepath}: {exc}") from exc


# --- Database Interactions ---


def execute_read(cfg: AppConfig, query: str, params: Tuple = ()) -> List[Tuple]:
    """Execute a read-only SQL query against the Pi-hole database."""
    try:
        db_uri = f"file:{cfg.db_path}?mode=ro"
        with sqlite3.connect(db_uri, uri=True, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    except sqlite3.Error as exc:
        raise RuntimeError(f"Database read failure: {exc}") from exc


def execute_deletions(
    cfg: AppConfig,
    delete_links_sql: str,
    delete_domains_sql: str,
    params: List[Tuple[str, ...]],
    err_context: str,
) -> None:
    """Execute domain and link deletion queries within a transaction."""
    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.executemany(delete_links_sql, params)
            cursor.executemany(delete_domains_sql, params)
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Database deletion transaction for {err_context} failed: {exc}"
        ) from exc


# --- Business Logic ---


def process_step1(cfg: AppConfig) -> None:
    """Merge default DB entries into whitelist.txt and remove them from DB."""
    query = """
        SELECT d.domain
        FROM domainlist d
        JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
        JOIN "group" g ON dg.group_id = g.id
        WHERE d.type = 0
        AND (d.comment IS NULL OR d.comment = '')
        AND g.name = 'Default'
    """

    db_entries_raw = execute_read(cfg, query)
    db_entries = frozenset(sanitize_domain(row[0]) for row in db_entries_raw)

    if not db_entries:
        logger.info("Step 1 Complete: No default DB entries require merging.")
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

    params = [(e,) for e in db_entries]
    delete_links = (
        "DELETE FROM domainlist_by_group WHERE domainlist_id IN "
        "(SELECT id FROM domainlist WHERE domain = ? AND type = 0)"
    )
    delete_domains = (
        "DELETE FROM domainlist WHERE domain = ? "
        "AND type = 0 AND (comment IS NULL OR comment = '')"
    )

    execute_deletions(cfg, delete_links, delete_domains, params, "step 1")

    run_command(
        ["docker", "exec", "pihole", "pihole", "reloadlists"],
        timeout=cfg.subprocess_timeout,
    )
    logger.info("Step 1 Complete: Extracted and merged %d entries.", len(db_entries))


def process_immutable_hosts(cfg: AppConfig) -> None:
    """Merge new 'hosts' DB entries eternally into whitelists/hosts.txt."""
    query = "SELECT domain FROM domainlist WHERE type = 0 AND comment = 'hosts'"
    db_entries_raw = execute_read(cfg, query)
    db_entries = frozenset(sanitize_domain(row[0]) for row in db_entries_raw)

    hosts_path = cfg.whitelists_dir / "hosts.txt"
    txt_entries: FrozenSet[str] = frozenset()

    if hosts_path.exists():
        try:
            with open(hosts_path, "r", encoding="utf-8") as file_obj:
                txt_entries = frozenset(
                    sanitize_domain(line) for line in file_obj if line.strip()
                )
        except IOError as exc:
            raise RuntimeError(f"Failed to read existing hosts.txt: {exc}") from exc

    if not db_entries:
        logger.info("No new 'hosts' entries to merge from DB.")
        return

    combined_entries = sorted(list(db_entries | txt_entries))
    write_atomic(hosts_path, combined_entries)

    params = [(e,) for e in db_entries]
    delete_links = (
        "DELETE FROM domainlist_by_group WHERE domainlist_id IN "
        "(SELECT id FROM domainlist WHERE domain = ? AND type = 0 AND comment = 'hosts')"
    )
    delete_domains = (
        "DELETE FROM domainlist WHERE domain = ? AND type = 0 AND comment = 'hosts'"
    )

    execute_deletions(cfg, delete_links, delete_domains, params, "hosts")

    logger.info(
        "Extracted, merged, and deleted %d 'hosts' entries from DB.",
        len(db_entries),
    )


def load_immutable_whitelist(cfg: AppConfig, filename: str) -> FrozenSet[str]:
    """Read an immutable whitelist file if present."""
    file_path = cfg.whitelists_dir / filename
    if not file_path.is_file():
        return frozenset()
    try:
        with open(file_path, "r", encoding="utf-8") as file_obj:
            domains = frozenset(
                sanitize_domain(line) for line in file_obj if line.strip()
            )
            logger.info(
                "Cataloged %d entries from immutable %s.", len(domains), filename
            )
            return domains
    except IOError as exc:
        logger.warning("Failed to read %s: %s", filename, exc)
        return frozenset()


def extract_categorized_whitelists(cfg: AppConfig) -> Dict[str, FrozenSet[str]]:
    """Parse DB and cluster domains into categories, ignoring immutables."""
    query = (
        "SELECT domain, comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != '' "
        "AND comment NOT IN ('healthcheck', 'hosts')"
    )
    rows = execute_read(cfg, query)

    temp_dict: Dict[str, Set[str]] = {}
    for domain, comment in rows:
        categories = parse_comment_categories(comment)
        sanitized_dom = sanitize_domain(domain)
        for cat in categories:
            temp_dict.setdefault(cat, set()).add(sanitized_dom)

    categories_result = {
        cat: frozenset(domains)
        for cat, domains in temp_dict.items()
        if len(domains) >= 2 or cat.lower() in ("healthcheck", "hosts")
    }

    for immutable_cat in ["healthcheck", "hosts"]:
        immutable_domains = load_immutable_whitelist(cfg, f"{immutable_cat}.txt")
        if immutable_domains:
            categories_result[immutable_cat] = immutable_domains

    return categories_result


def write_category_files(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Write generated categories to physical category files."""
    cfg.whitelists_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    for existing_file in cfg.whitelists_dir.glob("*.txt"):
        if existing_file.name.lower() in ("healthcheck.txt", "hosts.txt"):
            continue
        existing_file.unlink()

    for category, domains in categories.items():
        if category.lower() in ("healthcheck", "hosts"):
            logger.info(
                "Skipping write/overwrite for immutable file: %s.txt",
                category.lower(),
            )
            continue
        safe_filename = format_filename(category)
        file_path = cfg.whitelists_dir / f"{safe_filename}.txt"
        write_atomic(file_path, sorted(list(domains)))


def _assign_exclusive_group(cursor: sqlite3.Cursor, spec: GroupAssignmentSpec) -> None:
    """Exclusively assign domains/adlists matching comments to a group."""
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
    """Rebuild non-default group definitions and return group map."""
    cursor.execute('SELECT id FROM "group" WHERE id = 0')
    if cursor.fetchone() is None:
        raise RuntimeError("Integrity Error: Default group (id=0) missing.")

    cursor.execute("DELETE FROM client_by_group WHERE group_id != 0")
    cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
    cursor.execute('DELETE FROM "group" WHERE id != 0')

    sorted_categories = sorted(categories.keys())
    if "healthcheck" not in sorted_categories:
        sorted_categories.append("healthcheck")
    if "hosts" not in sorted_categories:
        sorted_categories.append("hosts")

    cursor.executemany(
        'INSERT INTO "group" (name, description) VALUES (?, ?)',
        [(cat, cat) for cat in sorted_categories],
    )

    cursor.execute('SELECT id, name FROM "group" WHERE id != 0')
    return {name: gid for gid, name in cursor.fetchall()}


def _assign_standard_domains(cursor: sqlite3.Cursor, group_map: Dict[str, int]) -> None:
    """Link non-exclusive domainlist entries exclusively to comment categories."""
    cursor.execute(
        "SELECT id, comment FROM domainlist "
        "WHERE comment IS NOT NULL AND comment != '' "
        "AND (comment NOT IN ('healthcheck', 'hosts') OR type IN (2, 3))"
    )

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
            "INSERT OR IGNORE INTO domainlist_by_group "
            "(domainlist_id, group_id) VALUES (?, ?)",
            domain_group_links,
        )


def rebuild_db_groups(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Rebuild Pi-hole DB groups safely preserving client associations."""
    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT cbg.client_id, g.name
                FROM client_by_group cbg
                JOIN "group" g ON cbg.group_id = g.id
                WHERE g.id != 0
            """
            )
            client_backups = cursor.fetchall()

            group_map = _recreate_groups(cursor, categories)
            _assign_standard_domains(cursor, group_map)

            hc_gid = group_map.get("healthcheck")
            hosts_gid = group_map.get("hosts")

            specs = [
                GroupAssignmentSpec(
                    table="domainlist",
                    link_table="domainlist_by_group",
                    fk_col="domainlist_id",
                    comments=("healthcheck", "healtcheck"),
                    group_id=hc_gid,
                    type_cond="type IN (0, 2)",
                ),
                GroupAssignmentSpec(
                    table="domainlist",
                    link_table="domainlist_by_group",
                    fk_col="domainlist_id",
                    comments=("hosts",),
                    group_id=hosts_gid,
                    type_cond="type IN (0, 2)",
                ),
                GroupAssignmentSpec(
                    table="adlist",
                    link_table="adlist_by_group",
                    fk_col="adlist_id",
                    comments=("healthcheck", "healtcheck"),
                    group_id=hc_gid,
                    type_cond="type = 1",
                ),
                GroupAssignmentSpec(
                    table="adlist",
                    link_table="adlist_by_group",
                    fk_col="adlist_id",
                    comments=("hosts",),
                    group_id=hosts_gid,
                    type_cond="type = 1",
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
                    "INSERT OR IGNORE INTO client_by_group "
                    "(client_id, group_id) VALUES (?, ?)",
                    client_group_links,
                )

        logger.info(
            "Steps 2 & 3 Complete: Successfully rebuilt %d database groups.",
            len(categories),
        )
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Database transaction failed during group rebuild: {exc}"
        ) from exc


def push_to_github(cfg: AppConfig) -> None:
    """Commit changes and push infrastructure changes to origin."""
    if not (cfg.repo_dir / ".git").is_dir():
        raise RuntimeError(f"Not a valid Git repository: {cfg.repo_dir}")

    run_command(
        [
            "git",
            "add",
            str(cfg.whitelist_txt_path.name),
            str(cfg.whitelists_dir.name),
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
        with subprocess.Popen(
            ["git", "push"],
            cwd=cfg.repo_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ):
            pass
        logger.info(
            "Step 4 Complete: Commit '%s' created and push dispatched.",
            commit_msg,
        )
    except Exception as exc:
        logger.error("Failed to start background git push: %s", exc)
        raise RuntimeError(f"Background push failed: {exc}") from exc


# --- Main Execution Control ---


def main() -> None:
    """Run the primary Pi-hole whitelist automation routine."""
    logger.info("Initializing Pi-hole Whitelist Automation...")
    try:
        cfg = AppConfig.load()

        process_step1(cfg)
        process_immutable_hosts(cfg)

        categories = extract_categorized_whitelists(cfg)
        if not categories:
            logger.info("No categorizable whitelists found. Skipping rebuild.")
            push_to_github(cfg)
            return

        write_category_files(cfg, categories)
        rebuild_db_groups(cfg, categories)

        run_command(
            ["docker", "exec", "pihole", "pihole", "reloadlists"],
            timeout=cfg.subprocess_timeout,
        )

        push_to_github(cfg)
        logger.info("Automation sequence completed successfully.")

    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.critical("FATAL ERROR: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
