"""
Module for synchronizing Pi-hole groups and whitelist files.
Automatically creates groups based on whitelist comments, maps domains,
and exports '#' prefixed categories to a separate text file.
"""

import fcntl
import re
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path
from types import MappingProxyType
from typing import Dict, List

# Define paths
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
LOCK_FILE_PATH = Path("/tmp/pihole_group_sync.lock")
WHITELIST_TXT_PATH = Path(__file__).parent / "whitelist.txt"

# Define immutable set of groups to skip
SKIPPED_GROUPS = frozenset(["Hosts"])

# Define the mandatory first group that must never be deleted
DEFAULT_GROUP = "Default"

# Define exact replacements for legacy corrupted data
CORRECTIONS = MappingProxyType(
    {
        "Microsoftoffice": "Microsoft Office",
        "Microsoftoutlook": "Microsoft Outlook",
        "Amazonkindle": "Amazon Kindle",
    }
)


def clean_to_title_case(text: str) -> str:
    """Sanitize control chars, normalize whitespace, apply corrections, and Title Case."""
    if not text:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f]+", "", str(text))
    clean = re.sub(r"\s+", " ", clean).strip().title()
    if clean in CORRECTIONS:
        return CORRECTIONS[clean]
    return clean


def is_valid_domain(domain: str) -> bool:
    """
    Robust checks to ensure the string is a valid, pure domain name.
    Rejects URLs with schemes (http://), invalid characters, or excessive lengths.
    """
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip()

    # Total length check (RFC 1035)
    if len(domain) > 253:
        return False

    # Regex for standard valid FQDNs
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )
    return bool(pattern.match(domain))


def process_and_clean_whitelist(cursor: sqlite3.Cursor) -> List[int]:
    """
    Parses whitelist.txt and gravity.db '#' entries, recreates whitelist.txt in
    alphabetical order, and returns the database IDs of migrated domains for deletion.
    """
    merged_data = defaultdict(set)
    current_comment = None

    # 1. Parse existing whitelist.txt file
    if WHITELIST_TXT_PATH.exists():
        with open(WHITELIST_TXT_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    current_comment = f"# {line.lstrip('#').strip()}"
                elif current_comment and is_valid_domain(line):
                    merged_data[current_comment].add(line)

    # 2. Extract '#' entries from the database along with their primary key IDs
    cursor.execute(
        "SELECT id, domain, comment FROM domainlist "
        "WHERE type = 0 AND comment LIKE '#%'"
    )
    db_entries = cursor.fetchall()

    db_ids_to_delete = []
    for domain_id, domain, comment in db_entries:
        clean_domain = domain.strip()
        clean_comment = f"# {comment.lstrip('#').strip()}"

        if is_valid_domain(clean_domain):
            merged_data[clean_comment].add(clean_domain)
            db_ids_to_delete.append(domain_id)

    # 3. Secure data in immutable structures
    immutable_whitelist = MappingProxyType(
        {comment: frozenset(domains) for comment, domains in merged_data.items()}
    )

    # 4. Re-create whitelist.txt from scratch in strict alphabetical order
    with open(WHITELIST_TXT_PATH, "w", encoding="utf-8") as f:
        for comment in sorted(immutable_whitelist.keys()):
            f.write(f"{comment}\n")
            for domain in sorted(immutable_whitelist[comment]):
                f.write(f"{domain}\n")
            f.write("\n")

    return db_ids_to_delete


def remove_migrated_domains(cursor: sqlite3.Cursor, ids_to_delete: List[int]):
    """Deletes migrated '#' domains and their group links from gravity.db."""
    if not ids_to_delete:
        return

    cursor.executemany(
        "DELETE FROM domainlist_by_group WHERE domainlist_id = ?",
        [(domain_id,) for domain_id in ids_to_delete],
    )
    cursor.executemany(
        "DELETE FROM domainlist WHERE id = ?",
        [(domain_id,) for domain_id in ids_to_delete],
    )
    print(f"Removed {len(ids_to_delete)} migrated '#' domain(s) from gravity.db.")


def sync_groups(cursor: sqlite3.Cursor) -> Dict[str, int]:
    """Ensures Default group exists, creates new groups, and returns group mapping."""
    cursor.execute('SELECT id, name FROM "group"')
    existing_group_dict = {}
    for group_id, name in cursor.fetchall():
        cleaned_name = clean_to_title_case(name)
        if cleaned_name:
            existing_group_dict[cleaned_name] = group_id

    current_timestamp = int(time.time())
    if DEFAULT_GROUP not in existing_group_dict:
        cursor.execute(
            'INSERT INTO "group" (name, date_added, date_modified, description) '
            "VALUES (?, ?, ?, ?)",
            (DEFAULT_GROUP, current_timestamp, current_timestamp, ""),
        )
        existing_group_dict[DEFAULT_GROUP] = cursor.lastrowid
        print(f"Created missing '{DEFAULT_GROUP}' group.")

    cursor.execute(
        "SELECT comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    )

    whitelisted_comments = set()
    for row in cursor.fetchall():
        if row[0].strip().startswith("#"):
            continue

        cleaned_comment = clean_to_title_case(row[0])
        if cleaned_comment and cleaned_comment not in SKIPPED_GROUPS:
            whitelisted_comments.add(cleaned_comment)

    new_groups = whitelisted_comments - set(existing_group_dict.keys())

    if new_groups:
        new_group_data = [
            (name, current_timestamp, current_timestamp, "")
            for name in sorted(new_groups)
        ]
        cursor.executemany(
            'INSERT INTO "group" (name, date_added, date_modified, description) '
            "VALUES (?, ?, ?, ?)",
            new_group_data,
        )

        cursor.execute('SELECT id, name FROM "group"')
        for group_id, name in cursor.fetchall():
            cleaned_name = clean_to_title_case(name)
            if cleaned_name:
                existing_group_dict[cleaned_name] = group_id

        print(f"Successfully inserted {len(new_groups)} new group(s).")

    return existing_group_dict


def map_domains_to_groups(cursor: sqlite3.Cursor, group_dict: Dict[str, int]):
    """Maps domains to their corresponding groups based on whitelist comments."""
    cursor.execute(
        "SELECT id, comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    )

    mapping_inserts = []
    for domain_id, comment in cursor.fetchall():
        if comment.strip().startswith("#"):
            continue

        cleaned_comment = clean_to_title_case(comment)
        if cleaned_comment and cleaned_comment in group_dict:
            group_id = group_dict[cleaned_comment]
            mapping_inserts.append((domain_id, group_id))

    if mapping_inserts:
        cursor.executemany(
            "INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) "
            "VALUES (?, ?)",
            mapping_inserts,
        )
        print(
            f"Successfully linked {len(mapping_inserts)} whitelist domain(s) "
            "to their corresponding groups."
        )


def run_sync():
    """Executes the complete database synchronization and file processing pipeline."""
    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        print(f"Processing and regenerating {WHITELIST_TXT_PATH.name}...")
        ids_to_delete = process_and_clean_whitelist(cursor)
        remove_migrated_domains(cursor, ids_to_delete)

        existing_groups = sync_groups(cursor)
        map_domains_to_groups(cursor, existing_groups)

        conn.commit()
        print(
            "Success: Database sync, entry migration, "
            "and file generation completed seamlessly."
        )

    except Exception as e:  # pylint: disable=broad-exception-caught
        conn.rollback()
        print(
            f"FATAL ERROR: Operation failed. Rolled back database changes.\n"
            f"Details: {e}"
        )
    finally:
        conn.close()


def main():
    """Main entry point for the Pi-hole sync script."""
    try:
        with open(LOCK_FILE_PATH, "w", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                print("ERROR: Another instance of this script is already running.")
                sys.exit(1)

            run_sync()
    except IOError as err:
        print(f"Failed to open or lock file: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
