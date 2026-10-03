import sqlite3
import subprocess
import os
import secrets
import re
import logging
import sys
from pathlib import Path

# --- Production Logging Setup (Essential Output Only) ---
logger = logging.getLogger("PiholeWhitelistManager")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)


# --- Path Resolution & Validation ---

def get_base_paths() -> tuple[Path, Path, Path]:
    db_path = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    repo_dir = Path(__file__).resolve().parent
    txt_path = repo_dir / "whitelist.txt"

    if not db_path.exists():
        raise FileNotFoundError(f"Pi-hole database does not exist at: {db_path}")
    if not repo_dir.exists():
        raise FileNotFoundError(f"Repository directory does not exist at: {repo_dir}")

    return db_path, txt_path, repo_dir


# --- Helper Utilities ---

def sanitize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise TypeError("Domain must be a string")
    return domain.strip().lower()


def parse_comment_categories(comment: str) -> list[str]:
    if not comment or not isinstance(comment, str):
        return []
    cleaned_comment = re.sub(r'\{.*?\}', '', comment)
    return [c.strip() for c in cleaned_comment.split('/') if c.strip()]


def format_filename(category: str) -> str:
    if not category or not isinstance(category, str):
        raise ValueError("Category must be a non-empty string")
    safe_chars = "".join(c for c in category if c.isalnum() or c in (' ', '_', '-')).strip()
    return re.sub(r'\s+', '_', safe_chars)


def restart_pihole() -> None:
    try:
        subprocess.run(
            ["docker", "exec", "pihole", "pihole", "restartdns", "reload-lists"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restart Pi-hole FTL: {e.stderr.strip() if e.stderr else e}")
        raise


def run_git_command(cmd: list[str], repo_dir: Path, capture_output: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            cmd,
            cwd=repo_dir,
            check=True,
            capture_output=capture_output,
            text=True
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else str(e)
        logger.error(f"Git command failed standard execution ({' '.join(cmd)}): {err_msg}")
        raise


# --- Core Processors ---

def process_step1(db_path: Path, txt_path: Path) -> None:
    query_select = """
        SELECT d.domain 
        FROM domainlist d
        JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
        JOIN "group" g ON dg.group_id = g.id
        WHERE d.type = 0 
        AND (d.comment IS NULL OR d.comment = '')
        AND g.name = 'Default'
    """
    
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0) as conn:
        cursor = conn.cursor()
        cursor.execute(query_select)
        db_entries = frozenset(sanitize_domain(row[0]) for row in cursor.fetchall())

    txt_entries = frozenset()
    if txt_path.exists():
        with open(txt_path, 'r', encoding='utf-8') as f:
            txt_entries = frozenset(sanitize_domain(line) for line in f if line.strip())

    if not db_entries:
        logger.info("Step 1: No default DB entries to process.")
        return

    combined = frozenset(db_entries | txt_entries)
    sorted_entries = sorted(list(combined))

    tmp_path = txt_path.with_suffix('.tmp')
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            for entry in sorted_entries:
                f.write(f"{entry}\n")
        os.replace(tmp_path, txt_path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        raise IOError(f"Failed to update whitelist.txt: {e}") from e

    params = [(e,) for e in db_entries]
    delete_links = "DELETE FROM domainlist_by_group WHERE domainlist_id IN (SELECT id FROM domainlist WHERE domain = ? AND type = 0)"
    delete_domains = "DELETE FROM domainlist WHERE domain = ? AND type = 0 AND (comment IS NULL OR comment = '')"

    with sqlite3.connect(db_path, timeout=10.0) as conn:
        cursor = conn.cursor()
        cursor.executemany(delete_links, params)
        cursor.executemany(delete_domains, params)

    restart_pihole()
    logger.info(f"Step 1 Complete: Merged {len(db_entries)} default entries into whitelist.txt and cleaned DB.")


def extract_categorized_whitelists(db_path: Path) -> dict[str, frozenset[str]]:
    query = "SELECT domain, comment FROM domainlist WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0) as conn:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()

    temp_dict: dict[str, set[str]] = {}
    for domain, comment in rows:
        sanitized_dom = sanitize_domain(domain)
        categories = parse_comment_categories(comment)
        for cat in categories:
            temp_dict.setdefault(cat, set()).add(sanitized_dom)

    return {cat: frozenset(domains) for cat, domains in temp_dict.items() if len(domains) >= 2}


def write_category_files(repo_dir: Path, categories: dict[str, frozenset[str]]) -> None:
    whitelists_dir = repo_dir / "whitelists"
    whitelists_dir.mkdir(exist_ok=True)

    if not os.access(whitelists_dir, os.W_OK):
        raise PermissionError(f"Directory {whitelists_dir} is not writable.")

    # Clean stale whitelist text files
    for existing_file in whitelists_dir.glob("*.txt"):
        existing_file.unlink()

    for category, domains in categories.items():
        safe_filename = format_filename(category)
        file_path = whitelists_dir / f"{safe_filename}.txt"
        tmp_path = whitelists_dir / f"{safe_filename}.tmp"

        with open(tmp_path, 'w', encoding='utf-8') as f:
            for domain in sorted(list(domains)):
                f.write(f"{domain}\n")

        os.replace(tmp_path, file_path)


def rebuild_db_groups(db_path: Path, categories: dict[str, frozenset[str]]) -> None:
    if not categories:
        raise ValueError("Categories dictionary cannot be empty during group rebuild.")

    with sqlite3.connect(db_path, timeout=10.0) as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM \"group\" WHERE id = 0")
        if cursor.fetchone() is None:
            raise RuntimeError("CRITICAL: Pi-hole default group (id=0) missing!")

        # 1. Backup client group assignments for non-default groups
        cursor.execute("""
            SELECT cbg.client_id, g.name 
            FROM client_by_group cbg
            JOIN "group" g ON cbg.group_id = g.id
            WHERE g.id != 0
        """)
        client_backups = cursor.fetchall()

        # 2. Clear old non-default groups and associations
        cursor.execute("DELETE FROM client_by_group WHERE group_id != 0")
        cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
        cursor.execute("DELETE FROM \"group\" WHERE id != 0")

        # 3. Insert new groups strictly in alphabetical order
        for cat_name in sorted(categories.keys()):
            cursor.execute("INSERT INTO \"group\" (name, description) VALUES (?, ?)", (cat_name, cat_name))

        cursor.execute("SELECT id, name FROM \"group\" WHERE id != 0")
        group_map = {name: gid for gid, name in cursor.fetchall()}

        # 4. Re-associate domains across all domain types (whitelists, blacklists, regex)
        cursor.execute("SELECT id, comment FROM domainlist WHERE comment IS NOT NULL AND comment != ''")
        domains_data = cursor.fetchall()

        domain_group_links = []
        for d_id, comment in domains_data:
            for ic in parse_comment_categories(comment):
                if ic in group_map:
                    domain_group_links.append((d_id, group_map[ic]))

        if domain_group_links:
            cursor.executemany("INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)", domain_group_links)

        # 5. Restore client group assignments matching newly recreated groups
        client_group_links = [
            (client_id, group_map[group_name]) 
            for client_id, group_name in client_backups 
            if group_name in group_map
        ]
        
        if client_group_links:
            cursor.executemany("INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?, ?)", client_group_links)

    logger.info(f"Steps 2 & 3 Complete: Rebuilt {len(categories)} groups in alphabetical order.")


def push_to_github(repo_dir: Path) -> None:
    if not (repo_dir / ".git").is_dir():
        raise RuntimeError(f"Directory is not a valid Git repository: {repo_dir}")

    run_git_command(["git", "add", "."], repo_dir)
    status_check = run_git_command(["git", "status", "--porcelain"], repo_dir, capture_output=True)

    if not status_check.stdout.strip():
        logger.info("Step 4 Complete: No repository changes to commit.")
        return

    commit_msg = secrets.token_hex(4)
    run_git_command(["git", "commit", "-m", commit_msg], repo_dir)
    run_git_command(["git", "push"], repo_dir)

    logger.info("Step 4 Complete: Pushed repository changes to GitHub.")


# --- Main Execution Entrypoint ---

def main() -> None:
    logger.info("Pi-hole Whitelist Automation started.")
    try:
        db_path, txt_path, repo_dir = get_base_paths()

        process_step1(db_path, txt_path)

        categories = extract_categorized_whitelists(db_path)
        if not categories:
            logger.info("No valid categories found. Skipping group rebuilding.")
            push_to_github(repo_dir)
            return

        write_category_files(repo_dir, categories)
        rebuild_db_groups(db_path, categories)

        restart_pihole()
        push_to_github(repo_dir)

        logger.info("Pi-hole Whitelist Automation completed successfully.")

    except Exception as e:
        logger.critical(f"Automation process failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
