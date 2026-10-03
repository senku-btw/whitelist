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

    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.executemany(delete_links, params)
            cursor.executemany(delete_domains, params)
    except sqlite3.Error as exc:
        raise RuntimeError(f"Database deletion transaction failed: {exc}") from exc

    run_command(
        ["docker", "exec", "pihole", "pihole", "reloadlists"],
        timeout=cfg.subprocess_timeout,
    )
    logger.info("Step 1 Complete: Extracted and merged %d entries.", len(db_entries))


def load_healthcheck_whitelist(cfg: AppConfig) -> FrozenSet[str]:
    """Read healthcheck.txt immutably if present, ignoring DB absence."""
    healthcheck_path = cfg.whitelists_dir / "healthcheck.txt"
    if not healthcheck_path.is_file():
        return frozenset()
    try:
        with open(healthcheck_path, "r", encoding="utf-8") as file_obj:
            domains = frozenset(
                sanitize_domain(line) for line in file_obj if line.strip()
            )
            logger.info(
                "Cataloged %d entries from immutable healthcheck.txt.",
                len(domains),
            )
            return domains
    except IOError as exc:
        logger.warning("Failed to read healthcheck.txt: %s", exc)
        return frozenset()


def extract_categorized_whitelists(
    cfg: AppConfig,
) -> Dict[str, FrozenSet[str]]:
    """Parse database and cluster domains into categories, ignoring exact healthcheck entries."""
    query = (
        "SELECT domain, comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != '' "
        "AND comment != 'healthcheck'"
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
        if len(domains) >= 2 or cat.lower() == "healthcheck"
    }

    # Incorporate healthcheck.txt catalog immutably, ensuring healthcheck group is created
    healthcheck_domains = load_healthcheck_whitelist(cfg)
    if healthcheck_domains:
        categories_result["healthcheck"] = healthcheck_domains

    return categories_result


def write_category_files(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Write generated categories to physical category files, protecting healthcheck.txt."""
    cfg.whitelists_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    for existing_file in cfg.whitelists_dir.glob("*.txt"):
        if existing_file.name.lower() == "healthcheck.txt":
            continue
        existing_file.unlink()

    for category, domains in categories.items():
        if category.lower() == "healthcheck":
            # Immutable file: never delete entries, never add entries, never overwrite.
            logger.info("Skipping write/overwrite for immutable file: healthcheck.txt")
            continue
        safe_filename = format_filename(category)
        file_path = cfg.whitelists_dir / f"{safe_filename}.txt"
        write_atomic(file_path, sorted(list(domains)))

def rebuild_db_groups(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    """Rebuild Pi-hole DB groups safely preserving client associations,
    keeping regex healthcheck entries, and exclusively assigning healthcheck allowlists.
    """
    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            cursor.execute('SELECT id FROM "group" WHERE id = 0')
            if cursor.fetchone() is None:
                raise RuntimeError("Integrity Error: Default group (id=0) missing.")

            cursor.execute(
                """
                SELECT cbg.client_id, g.name
                FROM client_by_group cbg
                JOIN "group" g ON cbg.group_id = g.id
                WHERE g.id != 0
            """
            )
            client_backups = cursor.fetchall()

            cursor.execute("DELETE FROM client_by_group WHERE group_id != 0")
            cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
            cursor.execute('DELETE FROM "group" WHERE id != 0')

            sorted_categories = sorted(categories.keys())
            
            # Ensure healthcheck group exists for assignment
            if "healthcheck" not in sorted_categories:
                sorted_categories.append("healthcheck")

            cursor.executemany(
                'INSERT INTO "group" (name, description) VALUES (?, ?)',
                [(cat, cat) for cat in sorted_categories],
            )

            cursor.execute('SELECT id, name FROM "group" WHERE id != 0')
            group_map = {name: gid for gid, name in cursor.fetchall()}
            hc_group_id = group_map.get("healthcheck")

            # Standard group assignment for domains
            cursor.execute(
                "SELECT id, comment FROM domainlist "
                "WHERE comment IS NOT NULL AND comment != '' "
                "AND (comment != 'healthcheck' OR type IN (2, 3))"
            )
            domain_group_links = []

            for d_id, comment in cursor.fetchall():
                for tag in parse_comment_categories(comment):
                    if tag in group_map:
                        domain_group_links.append((d_id, group_map[tag]))

            if domain_group_links:
                cursor.executemany(
                    "INSERT OR IGNORE INTO domainlist_by_group "
                    "(domainlist_id, group_id) VALUES (?, ?)",
                    domain_group_links,
                )

            # Exclusively assign healthcheck/healtcheck allowlists to the healthcheck group
            cursor.execute(
                "SELECT id FROM domainlist "
                "WHERE (comment = 'healthcheck' OR comment = 'healtcheck') "
                "AND type IN (0, 2)"
            )
            hc_allowlists = [row[0] for row in cursor.fetchall()]

            if hc_allowlists and hc_group_id is not None:
                # Remove from all other groups, including the default group 0
                cursor.executemany(
                    "DELETE FROM domainlist_by_group WHERE domainlist_id = ?",
                    [(d_id,) for d_id in hc_allowlists]
                )
                # Assign exclusively to the healthcheck group
                cursor.executemany(
                    "INSERT INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)",
                    [(d_id, hc_group_id) for d_id in hc_allowlists]
                )

            # Restore client associations
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
