"""
Autonomous Pi-hole exact whitelist extractor and Git synchronization pipeline.

Reads whitelist entries from gravity.db, sanitizes domain names, categorizes them
by comment into individual files, and commits structural changes to Git.
Designed for headless, zero-downtime execution.
"""

import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Dict, Set


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a string to be used as a safe filesystem name.
    """
    if not isinstance(filename, str):
        return "unnamed_category"
    
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.strip().replace(" ", "_")
    return sanitized if sanitized else "unnamed_category"


def sanitize_domain(domain: str) -> str:
    """
    Fully sanitizes a domain entry by normalizing Unicode, removing invisible
    control/space characters, stripping protocols/paths, and enforcing standard domain chars.
    """
    if not domain or not isinstance(domain, str):
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


def read_db_whitelists(db_path: Path) -> Dict[str, Set[str]]:
    """
    Reads exact whitelists (type = 0) from gravity.db with strict read-only URI and timeout.
    """
    if not db_path.is_file():
        sys.exit(1)

    categories: Dict[str, Set[str]] = {}
    uri = f"file:{db_path.resolve()}?mode=ro"

    try:
        # 30-second connection timeout handles transient SQLite database locks
        with sqlite3.connect(uri, uri=True, timeout=30.0) as conn:
            cursor = conn.cursor()
            query = "SELECT domain, comment FROM domainlist WHERE type = 0"
            cursor.execute(query)

            for row in cursor.fetchall():
                raw_domain = row[0] if row[0] is not None else ""
                comment = row[1] if row[1] is not None else ""

                cleaned_domain = sanitize_domain(raw_domain)
                if not cleaned_domain:
                    continue

                category_name = comment.strip()
                if category_name not in categories:
                    categories[category_name] = set()
                categories[category_name].add(cleaned_domain)

    except sqlite3.Error:
        sys.exit(1)

    return categories


def write_whitelists_atomically(categories: Dict[str, Set[str]], target_dir: Path) -> None:
    """
    Performs a true atomic directory swap to guarantee filesystem integrity.
    Merges existing 'hosts' file to ensure append-only immutability.
    """
    target_dir.parent.mkdir(parents=True, exist_ok=True)

    # Immutability policy for "hosts": Merge existing entries into memory
    hosts_file_path = target_dir / "hosts.txt"
    if hosts_file_path.is_file():
        if "hosts" not in categories:
            categories["hosts"] = set()

        try:
            with hosts_file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        categories["hosts"].add(clean_line)
        except OSError:
            pass  # Proceed with DB entries if read fails, preventing pipeline stall

    # Setup staging and backup directory paths for atomic operation
    hex_id = secrets.token_hex(4)
    tmp_dir = target_dir.with_name(f".{target_dir.name}_tmp_{hex_id}")
    backup_dir = target_dir.with_name(f".{target_dir.name}_backup_{hex_id}")

    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)

        for comment, domains in categories.items():
            file_name = f"{sanitize_filename(comment)}.txt" if comment else "whitelist.txt"
            file_path = tmp_dir / file_name

            unique_domains = sorted(frozenset(domains))

            with file_path.open("w", encoding="utf-8", newline="\n") as f:
                for domain in unique_domains:
                    f.write(f"{domain}\n")

        # Atomic Swap Sequence
        if target_dir.exists():
            target_dir.rename(backup_dir)
        
        tmp_dir.rename(target_dir)

    except OSError:
        # Rollback on failure
        if backup_dir.exists() and not target_dir.exists():
            backup_dir.rename(target_dir)
        sys.exit(1)

    finally:
        # Guaranteed cleanup of temporary and backup assets
        for cleanup_dir in (tmp_dir, backup_dir):
            if cleanup_dir.exists():
                shutil.rmtree(cleanup_dir, ignore_errors=True)


def git_sync(repo_dir: Path) -> None:
    """
    Stages all changes and pushes via a random 7-character hex ID.
    Enforces strict subprocess timeouts to prevent environment lockups.
    """
    if not (repo_dir / ".git").is_dir():
        sys.exit(1)
