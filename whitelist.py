import sqlite3
import subprocess
import os
import secrets
import re
from pathlib import Path

def get_base_paths() -> tuple[Path, Path, Path]:
    db_path = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    base_dir = db_path.parent
    txt_path = base_dir / "whitelist.txt"
    return db_path, base_dir, txt_path

def sanitize_domain(domain: str) -> str:
    return domain.strip().lower()

def parse_comment_categories(comment: str) -> list[str]:
    if not comment:
        return []
    cleaned_comment = re.sub(r'\{.*?\}', '', comment)
    return [c.strip() for c in cleaned_comment.split('/') if c.strip()]

def restart_pihole() -> None:
    subprocess.run(
        ["docker", "exec", "pihole", "pihole", "restartdns", "reload-lists"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def execute_db_read(db_path: Path, query: str, params: tuple = ()) -> list[tuple]:
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

def execute_db_write(db_path: Path, queries: tuple[str, list[tuple]]) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        for query, params in queries:
            cursor.executemany(query, params)
        conn.commit()

# --- Step 1 ---

def fetch_step1_db_entries(db_path: Path) -> frozenset[str]:
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
    return frozenset(sanitize_domain(row[0]) for row in rows)

def read_whitelist_txt(txt_path: Path) -> frozenset[str]:
    if not txt_path.exists():
        return frozenset()
    with open(txt_path, 'r') as f:
        return frozenset(sanitize_domain(line) for line in f if line.strip())

def write_combined_whitelist(txt_path: Path, combined_entries: frozenset[str]) -> None:
    sorted_entries = sorted(list(combined_entries))
    with open(txt_path, 'w') as f:
        for entry in sorted_entries:
            f.write(f"{entry}\n")

def delete_step1_db_entries(db_path: Path, entries: frozenset[str]) -> None:
    if not entries:
        return
    params = [(e,) for e in entries]
    queries = (
        ("DELETE FROM domainlist_by_group WHERE domainlist_id IN (SELECT id FROM domainlist WHERE domain = ? AND type = 0)", params),
        ("DELETE FROM domainlist WHERE domain = ? AND type = 0 AND (comment IS NULL OR comment = '')", params)
    )
    execute_db_write(db_path, queries)

def process_step1(db_path: Path, txt_path: Path) -> None:
    db_entries = fetch_step1_db_entries(db_path)
    txt_entries = read_whitelist_txt(txt_path)
    
    if not db_entries:
        return

    combined = frozenset(db_entries | txt_entries)
    write_combined_whitelist(txt_path, combined)
    
    delete_step1_db_entries(db_path, db_entries)
    restart_pihole()

# --- Step 2 ---

def extract_categorized_whitelists(db_path: Path) -> dict[str, frozenset[str]]:
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
            
    return final_dict

def format_filename(category: str) -> str:
    safe_chars = "".join(c for c in category if c.isalnum() or c in (' ', '_', '-')).strip()
    return re.sub(r'\s+', '_', safe_chars)

def write_category_files(base_dir: Path, categories: dict[str, frozenset[str]]) -> None:
    whitelists_dir = base_dir / "whitelists"
    whitelists_dir.mkdir(exist_ok=True)
    
    for category, domains in categories.items():
        safe_filename = format_filename(category)
        file_path = whitelists_dir / f"{safe_filename}.txt"
        sorted_domains = sorted(list(domains))
        
        with open(file_path, 'w') as f:
            for domain in sorted_domains:
                f.write(f"{domain}\n")

# --- Step 3 ---

def rebuild_db_groups(db_path: Path, categories: dict[str, frozenset[str]]) -> None:
    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM domainlist_by_group WHERE group_id != 0")
        cursor.execute("DELETE FROM \"group\" WHERE id != 0")
        
        for cat_name in categories.keys():
            cursor.execute("INSERT INTO \"group\" (name, description) VALUES (?, ?)", (cat_name, f"Auto-generated group for {cat_name}"))
            
        cursor.execute("SELECT id, name FROM \"group\" WHERE id != 0")
        group_map = {name: gid for gid, name in cursor.fetchall()}
        
        cursor.execute("SELECT id, domain, comment FROM domainlist WHERE type = 0")
        domains_data = cursor.fetchall()
        
        domain_group_links = []
        for d_id, domain, comment in domains_data:
            item_categories = parse_comment_categories(comment)
            for ic in item_categories:
                if ic in group_map:
                    domain_group_links.append((d_id, group_map[ic]))
                    
        cursor.executemany("INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)", domain_group_links)
        conn.commit()

# --- Step 4 ---

def push_to_github(base_dir: Path) -> None:
    commit_msg = secrets.token_hex(4)
    
    subprocess.run(["git", "add", "."], cwd=base_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "commit", "-m", commit_msg], cwd=base_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "push"], cwd=base_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --- Main Execution ---

def main() -> None:
    try:
        db_path, base_dir, txt_path = get_base_paths()
        
        process_step1(db_path, txt_path)
        
        categories = extract_categorized_whitelists(db_path)
        write_category_files(base_dir, categories)
        
        rebuild_db_groups(db_path, categories)
        
        restart_pihole()
        push_to_github(base_dir)
        
    except Exception:
        pass

if __name__ == "__main__":
    main()
