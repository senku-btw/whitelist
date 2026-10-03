import sqlite3
import subprocess
import os
import re
import logging
import sys
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import Iterable, List, Dict, FrozenSet, Tuple, Optional

# --- Production Logging Setup ---
logger = logging.getLogger("PiholeWhitelistManager")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)


# --- Configuration ---
@dataclass(frozen=True)
class AppConfig:
    db_path: Path
    repo_dir: Path
    whitelist_txt_path: Path
    whitelists_dir: Path
    subprocess_timeout: int = 30
    db_timeout: float = 10.0

    @classmethod
    def load(cls) -> 'AppConfig':
        default_db_path = os.getenv(
            "PIHOLE_DB_PATH", 
            "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"
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
            whitelists_dir=repo_dir / "whitelists"
        )


# --- Core Utilities ---

def sanitize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise TypeError(f"Expected string for domain, got {type(domain).__name__}")
    return domain.strip().lower()

def parse_comment_categories(comment: Optional[str]) -> List[str]:
    if not comment or not isinstance(comment, str):
        return []
    cleaned_comment = re.sub(r'\{.*?\}', '', comment)
    return [c.strip() for c in cleaned_comment.split('/') if c.strip()]

def format_filename(category: str) -> str:
    if not category:
        raise ValueError("Category name cannot be empty")
    safe_chars = "".join(c for c in category if c.isalnum() or c in (' ', '_', '-')).strip()
    return re.sub(r'\s+', '_', safe_chars)

def run_command(cmd: List[str], cwd: Optional[Path] = None, capture_output: bool = False, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            cwd=cwd,
            check=True,
            capture_output=capture_output,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired as e:
        logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise RuntimeError(f"Command timeout: {' '.join(cmd)}") from e
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else str(e)
        logger.error(f"Command failed ({' '.join(cmd)}): {err_msg}")
        raise RuntimeError(f"Command execution failed: {err_msg}") from e

def write_atomic(filepath: Path, lines: Iterable[str]) -> None:
    filepath.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=filepath.parent, delete=False, encoding='utf-8') as f:
            tmp_path = Path(f.name)
            for line in lines:
                f.write(f"{line}\n")
            f.flush()
            os.fsync(f.fileno()) 
            
        os.chmod(tmp_path, 0o644) 
        os.replace(tmp_path, filepath) 
    except Exception as e:
        if 'tmp_path' in locals() and tmp_path.exists():
            tmp_path.unlink()
        raise IOError(f"Atomic write failed for {filepath}: {e}") from e


# --- Database Interactions ---

def execute_read(cfg: AppConfig, query: str, params: Tuple = ()) -> List[Tuple]:
    try:
        with sqlite3.connect(f"file:{cfg.db_path}?mode=ro", uri=True, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    except sqlite3.Error as e:
        raise RuntimeError(f"Database read failure: {e}") from e


# --- Business Logic ---

def process_step1(cfg: AppConfig) -> None:
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
            with open(cfg.whitelist_txt_path, 'r', encoding='utf-8') as f:
                txt_entries = frozenset(sanitize_domain(line) for line in f if line.strip())
        except IOError as e:
            raise RuntimeError(f"Failed to read existing whitelist.txt: {e}") from e

    combined_entries = sorted(list(db_entries | txt_entries))
    write_atomic(cfg.whitelist_txt_path, combined_entries)

    params = [(e,) for e in db_entries]
    delete_links = "DELETE FROM domainlist_by_group WHERE domainlist_id IN (SELECT id FROM domainlist WHERE domain = ? AND type = 0)"
    delete_domains = "DELETE FROM domainlist WHERE domain = ? AND type = 0 AND (comment IS NULL OR comment = '')"

    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            cursor = conn.cursor()
            cursor.executemany(delete_links, params)
            cursor.executemany(delete_domains, params)
    except sqlite3.Error as e:
        raise RuntimeError(f"Database deletion transaction failed: {e}") from e

    run_command(["docker", "exec", "pihole", "pihole", "reloadlists"], timeout=cfg.subprocess_timeout)
    logger.info(f"Step 1 Complete: Extracted and merged {len(db_entries)} entries.")


def extract_categorized_whitelists(cfg: AppConfig) -> Dict[str, FrozenSet[str]]:
    query = "SELECT domain, comment FROM domainlist WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    rows = execute_read(cfg, query)

    temp_dict: Dict[str, set[str]] = {}
    for domain, comment in rows:
        categories = parse_comment_categories(comment)
        sanitized_dom = sanitize_domain(domain)
        for cat in categories:
            temp_dict.setdefault(cat, set()).add(sanitized_dom)

    return {cat: frozenset(domains) for cat, domains in temp_dict.items() if len(domains) >= 2}


def write_category_files(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    cfg.whitelists_dir.mkdir(parents=True, exist_ok=True, mode=0o755)

    for existing_file in cfg.whitelists_dir.glob("*.txt"):
        existing_file.unlink()

    for category, domains in categories.items():
        safe_filename = format_filename(category)
        file_path = cfg.whitelists_dir / f"{safe_filename}.txt"
        write_atomic(file_path, sorted(list(domains)))


def rebuild_db_groups(cfg: AppConfig, categories: Dict[str, FrozenSet[str]]) -> None:
    try:
        with sqlite3.connect(cfg.db_path, timeout=cfg.db_timeout) as conn:
            conn.execute("PRAGMA foreign_keys = ON")
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM \"group\" WHERE id = 0")
            if cursor.fetchone() is None:
                raise RuntimeError("Integrity Error: Default group (id=0) missing from Pi-hole database.")

            cursor.execute("""
                SELECT cbg.client_id, g.name 
                FROM client_by_group cbg
                JOIN "group" g ON cbg.group_id = g.id
                WHERE g.id != 0
            """)
            client_backups = cursor.fetchall()

            cursor.execute("DELETE FROM client_by_group WHERE group_id != 0")
            cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
            cursor.execute("DELETE FROM \"group\" WHERE id != 0")

            sorted_categories = sorted(categories.keys())
            cursor.executemany(
                "INSERT INTO \"group\" (name, description) VALUES (?, ?)", 
                [(cat, cat) for cat in sorted_categories]
            )

            cursor.execute("SELECT id, name FROM \"group\" WHERE id != 0")
            group_map = {name: gid for gid, name in cursor.fetchall()}

            cursor.execute("SELECT id, comment FROM domainlist WHERE comment IS NOT NULL AND comment != ''")
            domain_group_links = []
            
            for d_id, comment in cursor.fetchall():
                for tag in parse_comment_categories(comment):
                    if tag in group_map:
                        domain_group_links.append((d_id, group_map[tag]))

            if domain_group_links:
                cursor.executemany(
                    "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)", 
                    domain_group_links
                )

            client_group_links = [
                (client_id, group_map[group_name]) 
                for client_id, group_name in client_backups 
                if group_name in group_map
            ]
            
            if client_group_links:
                cursor.executemany(
                    "INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?, ?)", 
                    client_group_links
                )

        logger.info(f"Steps 2 & 3 Complete: Successfully rebuilt {len(categories)} database groups.")
    except sqlite3.Error as e:
        raise RuntimeError(f"Database transaction failed during group rebuild: {e}") from e


def push_to_github(cfg: AppConfig) -> None:
    if not (cfg.repo_dir / ".git").is_dir():
        raise RuntimeError(f"Not a valid Git repository: {cfg.repo_dir}")

    # Explicitly add only the required files to prevent sensitive data leaks
    run_command(
        ["git", "add", str(cfg.whitelist_txt_path.name), str(cfg.whitelists_dir.name)], 
        cwd=cfg.repo_dir, 
        timeout=cfg.subprocess_timeout
    )
    
    status = run_command(["git", "status", "--porcelain"], cwd=cfg.repo_dir, capture_output=True, timeout=cfg.subprocess_timeout)
    if not status.stdout.strip():
        logger.info("Step 4 Complete: No file modifications detected. Skipping Git push.")
        return

    commit_msg = f"auto-update-{os.urandom(4).hex()}"
    run_command(["git", "commit", "-m", commit_msg], cwd=cfg.repo_dir, timeout=cfg.subprocess_timeout)
    run_command(["git", "push"], cwd=cfg.repo_dir, timeout=cfg.subprocess_timeout * 2) 

    logger.info(f"Step 4 Complete: Pushed commit '{commit_msg}' to GitHub.")


# --- Main Execution Control ---

def main() -> None:
    logger.info("Initializing Pi-hole Whitelist Automation...")
    try:
        cfg = AppConfig.load()

        process_step1(cfg)

        categories = extract_categorized_whitelists(cfg)
        if not categories:
            logger.info("No categorizable whitelists found. Skipping rebuild step.")
            push_to_github(cfg)
            return

        write_category_files(cfg, categories)
        rebuild_db_groups(cfg, categories)

        run_command(["docker", "exec", "pihole", "pihole", "reloadlists"], timeout=cfg.subprocess_timeout)
        
        push_to_github(cfg)
        logger.info("Automation sequence completed successfully.")

    except Exception as e:
        logger.critical(f"FATAL ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
