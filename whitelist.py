#!/usr/bin/env python3
import sqlite3
import sys
import re
import unicodedata
from pathlib import Path
from typing import Dict, List

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a string to be used as a safe filesystem name.
    """
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    return sanitized.strip().replace(" ", "_")

def sanitize_domain(domain: str) -> str:
    """
    Fully sanitizes a domain entry by normalizing Unicode, removing invisible 
    control/space characters, stripping protocols/paths, and enforcing standard domain chars.
    """
    if not domain:
        return ""
    
    # 1. Normalize Unicode (NFKC)
    domain = unicodedata.normalize("NFKC", domain)
    
    # 2. Strip non-printable control characters (C) and space separators (Zs)
    domain = "".join(
        ch for ch in domain 
        if not unicodedata.category(ch).startswith("C") and unicodedata.category(ch) != "Zs"
    )
    
    # 3. Outer trim and lowercase
    domain = domain.strip().lower()
    
    # 4. Strip protocol
    domain = re.sub(r"^https?://", "", domain)
    
    # 5. Strip URI paths, parameters, anchors
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    
    # 6. Filter out invalid domain characters
    domain = re.sub(r"[^a-z0-9\.\-\_\*]", "", domain)
    
    # 7. Trim boundary dots/hyphens
    return domain.strip(".-")

def extract_whitelists(db_path: Path, output_dir: Path) -> None:
    """
    Reads exact whitelists from gravity.db, categorizes them, sanitizes entries, 
    and writes each group to its respective output file.
    """
    if not db_path.is_file():
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    categories: Dict[str, List[str]] = {}
    
    try:
        uri = f"file:{db_path.resolve()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            cursor = conn.cursor()
            
            # Type 0 = Exact Whitelist in Pi-hole domainlist
            query = "SELECT domain, comment FROM domainlist WHERE type = 0"
            cursor.execute(query)
            
            for row in cursor.fetchall():
                raw_domain, comment = row[0], row[1]
                
                cleaned_domain = sanitize_domain(raw_domain)
                if not cleaned_domain:
                    continue
                
                category_name = comment.strip() if comment and comment.strip() else ""
                
                if category_name not in categories:
                    categories[category_name] = []
                categories[category_name].append(cleaned_domain)
                
    except sqlite3.Error:
        sys.exit(1)

    write_output_files(categories, output_dir)

def write_output_files(categories: Dict[str, List[str]], output_dir: Path) -> None:
    """
    Deduplicates entries via frozenset, sorts them alphabetically, 
    and writes each domain to its own distinct line, completely overwriting prior files.
    """
    for comment, domains in categories.items():
        file_name = "whitelist.txt" if not comment else f"{sanitize_filename(comment)}.txt"
        file_path = output_dir / file_name

        try:
            # Enforce immutable deduplication and alphabetical order
            unique_domains = sorted(frozenset(domains))

            # Always overwrite ("w") and enforce standard Unix newline ("\n")
            with file_path.open("w", encoding="utf-8", newline="\n") as f:
                for domain in unique_domains:
                    f.write(f"{domain}\n")
                    
        except OSError:
            sys.exit(1)

if __name__ == "__main__":
    current_dir = Path(__file__).parent.resolve()
    whitelists_dir = current_dir / "whitelists"
    gravity_db = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    
    extract_whitelists(gravity_db, whitelists_dir)
    sys.exit(0)
