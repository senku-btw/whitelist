import sqlite3
import subprocess
import os
import secrets
import re
import logging
import sys
from pathlib import Path

# Configure logging to output only to stdout (RAM/console)
logger = logging.getLogger("PiholeWhitelistManager")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s')
handler.setFormatter(formatter)
if not logger.handlers:
    logger.addHandler(handler)

def get_base_paths() -> tuple[Path, Path, Path]:
    db_path = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    
    # Dynamically resolve the directory where this script is located (the Git repository root)
    repo_dir = Path(__file__).resolve().parent 
    
    # All target files and folders must be in the script's repository directory
    txt_path = repo_dir / "whitelist.txt"
    
    assert db_path.exists(), f"Pi-hole database does not exist: {db_path}"
    assert repo_dir.exists(), f"Repository directory does not exist: {repo_dir}"
    return db_path, txt_path, repo_dir

def sanitize_domain(domain: str) -> str:
    assert isinstance(domain, str), "Domain must be a string"
    return domain.strip().lower()

def parse_comment_categories(comment: str) -> list[str]:
    if not comment:
        return []
    assert isinstance(comment, str), "Comment must be a string"
    cleaned_comment = re.sub(r'\{.*?\}', '', comment)
    return [c.strip() for c in cleaned_comment.split('/') if c.strip()]

def restart_pihole() -> None:
    logger.info("Restarting Pi-hole FTL engine via Docker...")
    try:
        subprocess.run(
            ["docker", "exec", "pihole", "pihole", "restartdns", "reload-lists"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        logger.info("Pi-hole restarted successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to restart Pi-hole: {e}")
        raise

def execute_db_read(db_path: Path, query: str, params: tuple = ()) -> list[tuple]:
    assert db_path.exists(), f"Database not found at {db_path}"
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()
    except sqlite3.Error as e:
        logger.error(f"Database read error: {e}")
        raise

def execute_db_write(db_path: Path, queries: tuple[tuple[str, list[tuple]], ...]) -> None:
    assert db_path.exists(), f"Database not found at {db_path}"
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            for query, params in queries:
                cursor.executemany(query, params)
            logger.debug(f"Executed {len(queries)} write operations successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database write transaction failed and was rolled back: {e}")
        raise

# --- Step 1 ---

def fetch_step1_db_entries(db_path: Path) -> frozenset[str]:
    logger.info("Fetching default whitelist entries with empty comments from gravity.db...")
    query = """
        SELECT d.domain 
        FROM domainlist d
        JOIN domainlist_by_group dg ON d.id = dg.domainlist_id
        JOIN "group" g ON dg.group_id = g.id
        WHERE d.type = 0 
        AND (d.comment IS NULL OR d.comment = '')
        AND g.name = 'Default'
    """
    rows = execute_db_read(db_path, query)
    entries = frozenset(sanitize_domain(row[0]) for row in rows)
    logger.info(f"Found {len(entries)} matching entries in DB.")
    return entries

def read_whitelist_txt(txt_path: Path) -> frozenset[str]:
    logger.info(f"Reading existing whitelist file at {txt_path}...")
    if not txt_path.exists():
        logger.info("whitelist.txt does not exist in script directory. Returning empty set.")
        return frozenset()
    
    try:
        with open(txt_path, 'r') as f:
            entries = frozenset(sanitize_domain(line) for line in f if line.strip())
        logger.info(f"Read {len(entries)} entries from whitelist.txt.")
        return entries
    except IOError as e:
        logger.error(f"Failed to read whitelist.txt: {e}")
        raise

def write_combined_whitelist(txt_path: Path, combined_entries: frozenset[str]) -> None:
    assert isinstance(combined_entries, frozenset), "Entries must be a frozenset"
    logger.info(f"Writing {len(combined_entries)} combined entries to {txt_path} atomically...")
    sorted_entries = sorted(list(combined_entries))
    
    tmp_path = txt_path.with_suffix('.tmp')
    try:
        with open(tmp_path, 'w') as f:
            for entry in sorted_entries:
                f.write(f"{entry}\n")
        os.replace(tmp_path, txt_path)
        logger.info("Successfully updated whitelist.txt in script directory.")
    except IOError as e:
        logger.error(f"Failed to write combined whitelist: {e}")
        if tmp_path.exists():
            tmp_path.unlink()
        raise

def delete_step1_db_entries(db_path: Path, entries: frozenset[str]) -> None:
    if not entries:
        return
    logger.info(f"Deleting {len(entries)} processed entries from gravity.db...")
    params = [(e,) for e in entries]
    queries = (
        ("DELETE FROM domainlist_by_group WHERE domainlist_id IN (SELECT id FROM domainlist WHERE domain = ? AND type = 0)", params),
        ("DELETE FROM domainlist WHERE domain = ? AND type = 0 AND (comment IS NULL OR comment = '')", params)
    )
    execute_db_write(db_path, queries)
    logger.info("Database cleanup for Step 1 complete.")

def process_step1(db_path: Path, txt_path: Path) -> None:
    logger.info("--- Starting Step 1: Default Whitelist Processing ---")
    try:
        db_entries = fetch_step1_db_entries(db_path)
        txt_entries = read_whitelist_txt(txt_path)
        
        if not db_entries:
            logger.info("No DB entries to process for Step 1. Moving on.")
            return

        combined = frozenset(db_entries | txt_entries)
        write_combined_whitelist(txt_path, combined)
        
        delete_step1_db_entries(db_path, db_entries)
        restart_pihole()
        logger.info("Step 1 completed successfully.")
    except Exception as e:
        logger.critical(f"Step 1 failed: {e}")
        raise

# --- Step 2 ---

def extract_categorized_whitelists(db_path: Path) -> dict[str, frozenset[str]]:
    logger.info("--- Starting Step 2: Extracting Categorized Whitelists ---")
    query = "SELECT domain, comment FROM domainlist WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    rows = execute_db_read(db_path, query)
    
    temp_dict: dict[str, set[str]] = {}
    for domain, comment in rows:
        sanitized_dom = sanitize_domain(domain)
        categories = parse_comment_categories(comment)
        
        for cat in categories:
            if cat not in temp_dict:
                temp_dict[cat] = set()
            temp_dict[cat].add(sanitized_dom)
            
    final_dict: dict[str, frozenset[str]] = {}
    for cat, domains in temp_dict.items():
        if len(domains) >= 2:
            final_dict[cat] = frozenset(domains)
            
    logger.info(f"Extracted {len(final_dict)} valid categories with 2+ domains.")
    return final_dict

def format_filename(category: str) -> str:
    assert isinstance(category, str) and category, "Category must be a non-empty string"
    safe_chars = "".join(c for c in category if c.isalnum() or c in (' ', '_', '-')).strip()
    return re.sub(r'\s+', '_', safe_chars)

def write_category_files(repo_dir: Path, categories: dict[str, frozenset[str]]) -> None:
    # Whitelists folder is created directly in the script's repository directory
    whitelists_dir = repo_dir / "whitelists"
    logger.info(f"Writing category files to {whitelists_dir}...")
    
    try:
        whitelists_dir.mkdir(exist_ok=True)
        assert whitelists_dir.is_dir() and os.access(whitelists_dir, os.W_OK), "Whitelists directory is not writable"
        
        # Clean out existing .txt files in whitelists/ to prevent stale files from persisting in Git
        for existing_file in whitelists_dir.glob("*.txt"):
            existing_file.unlink()
        
        for category, domains in categories.items():
            safe_filename = format_filename(category)
            file_path = whitelists_dir / f"{safe_filename}.txt"
            tmp_path = whitelists_dir / f"{safe_filename}.tmp"
            
            sorted_domains = sorted(list(domains))
            
            with open(tmp_path, 'w') as f:
                for domain in sorted_domains:
                    f.write(f"{domain}\n")
            
            os.replace(tmp_path, file_path)
            
        logger.info("Category files generated atomically in script directory.")
    except Exception as e:
        logger.error(f"Failed to write category files: {e}")
        raise

# --- Step 3 ---

def rebuild_db_groups(db_path: Path, categories: dict[str, frozenset[str]]) -> None:
    logger.info("--- Starting Step 3: Rebuilding Database Groups ---")
    assert categories, "Categories dictionary cannot be empty"
    
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM \"group\" WHERE id = 0")
            assert cursor.fetchone() is not None, "CRITICAL: Default group (id=0) missing!"
            
            logger.info("Clearing old non-default groups and relationships...")
            cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
            cursor.execute("DELETE FROM \"group\" WHERE id != 0")
            
            logger.info("Inserting new groups...")
            for cat_name in categories.keys():
                # Modification A: Set description to just the category name instead of "Auto-generated..."
                cursor.execute("INSERT INTO \"group\" (name, description) VALUES (?, ?)", 
                               (cat_name, cat_name))
                
            cursor.execute("SELECT id, name FROM \"group\" WHERE id != 0")
            group_map = {name: gid for gid, name in cursor.fetchall()}
            
            logger.info("Re-associating domains with groups...")
            # Modification B: Removed `WHERE type = 0` to iterate through ALL domain types (whitelists, blacklists, regex)
            cursor.execute("SELECT id, domain, comment FROM domainlist")
            domains_data = cursor.fetchall()
            
            domain_group_links = []
            for d_id, domain, comment in domains_data:
                if not comment:
                    continue
                item_categories = parse_comment_categories(comment)
                for ic in item_categories:
                    if ic in group_map:
                        domain_group_links.append((d_id, group_map[ic]))
                        
            cursor.executemany("INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)", domain_group_links)
        logger.info("Database groups rebuilt successfully.")
    except sqlite3.Error as e:
        logger.critical(f"Failed to rebuild DB groups (Transaction Rolled Back): {e}")
        raise

# --- Step 4 ---

def push_to_github(repo_dir: Path) -> None:
    logger.info(f"--- Starting Step 4: Pushing to GitHub from {repo_dir} ---")
    
    try:
        assert (repo_dir / ".git").exists(), f"Not a git repository: {repo_dir}"
        
        subprocess.run(["git", "add", "."], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        status_check = subprocess.run(
            ["git", "status", "--porcelain"], 
            cwd=repo_dir, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        if not status_check.stdout.strip():
            logger.info("No modifications detected in the repository. Skipping commit and push.")
            return

        commit_msg = secrets.token_hex(4)
        logger.info(f"Generated secure commit message: {commit_msg}")
        
        subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["git", "push"], cwd=repo_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        logger.info("Successfully pushed changes to GitHub.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Git operation failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error during Git execution: {e}")
        raise

# --- Main Execution ---

def main() -> None:
    logger.info("=== Pi-hole Whitelist Automation Started ===")
    try:
        db_path, txt_path, repo_dir = get_base_paths()
        
        process_step1(db_path, txt_path)
        
        categories = extract_categorized_whitelists(db_path)
        if not categories:
            logger.info("No valid categories found in Step 2. Ending execution early to prevent wiping groups.")
            push_to_github(repo_dir)
            return
            
        write_category_files(repo_dir, categories)
        rebuild_db_groups(db_path, categories)
        
        restart_pihole()
        push_to_github(repo_dir)
        
        logger.info("=== Pi-hole Whitelist Automation Completed Successfully ===")
        
    except AssertionError as ae:
        logger.critical(f"Assertion Failure (Constraint violated): {ae}")
    except Exception as e:
        logger.critical(f"Catastrophic Failure: Script terminated early due to {e}")
    finally:
        logging.shutdown()

if __name__ == "__main__":
    main()
