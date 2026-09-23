"""
Module for synchronizing Pi-hole groups and whitelist files.
Automatically creates groups based on whitelist comments, maps domains,
preserves client associations, exports '#' prefixed categories to a text file,
and pushes to GitHub autonomously.
"""

import fcntl
import os
import re
import secrets
import sqlite3
import subprocess
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

# Git configuration defaults for automated execution
GIT_BOT_NAME = "Pi-hole Auto Sync Bot"
GIT_BOT_EMAIL = "pihole-bot@users.noreply.github.com"
GIT_TIMEOUT_SECONDS = 30


def generate_mixed_hex_comment(length: int = 7) -> str:
    """Generates a random hex string guaranteed to contain both digits and letters (a-f)."""
    while True:
        token = secrets.token_hex(4)[:length]
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return token


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

    if len(domain) > 253:
        return False

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

    immutable_whitelist = MappingProxyType(
        {comment: frozenset(domains) for comment, domains in merged_data.items()}
    )

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


def backup_client_mappings(cursor: sqlite3.Cursor) -> Dict[int, List[str]]:
    """Records current client-to-group configurations before the database is purged."""
    cursor.execute(
        """
        SELECT cbg.client_id, g.name
        FROM client_by_group cbg
        JOIN "group" g ON cbg.group_id = g.id
        """
    )
    client_backup = defaultdict(list)
    for client_id, group_name in cursor.fetchall():
        client_backup[client_id].append(group_name)

    return dict(client_backup)


def sync_groups(cursor: sqlite3.Cursor) -> Dict[str, int]:
    """
    Purges all non-Default groups and all group mappings across all tables,
    recreates missing groups, and returns a dictionary mapping group names to IDs.
    """
    current_timestamp = int(time.time())

    cursor.execute('SELECT id FROM "group" WHERE name = ?', (DEFAULT_GROUP,))
    default_row = cursor.fetchone()

    if default_row:
        default_group_id = default_row[0]
    else:
        cursor.execute(
            'INSERT INTO "group" (name, date_added, date_modified, description) '
            "VALUES (?, ?, ?, ?)",
            (DEFAULT_GROUP, current_timestamp, current_timestamp, ""),
        )
        default_group_id = cursor.lastrowid
        print(f"Created missing '{DEFAULT_GROUP}' group.")

    # Clear non-default associations across all relational tables
    cursor.execute(
        "DELETE FROM domainlist_by_group WHERE group_id != ?", (default_group_id,)
    )
    cursor.execute(
        "DELETE FROM client_by_group WHERE group_id != ?", (default_group_id,)
    )
    cursor.execute(
        "DELETE FROM adlist_by_group WHERE group_id != ?", (default_group_id,)
    )

    # Delete all groups except 'Default'
    cursor.execute('DELETE FROM "group" WHERE id != ?', (default_group_id,))
    print("Purged all previous non-Default groups and associated mappings.")

    cursor.execute(
        "SELECT comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    )

    whitelisted_comments = set()
    for row in cursor.fetchall():
        if row[0].strip().startswith("#"):
            continue

        cleaned_comment = clean_to_title_case(row[0])
        if (
            cleaned_comment
            and cleaned_comment not in SKIPPED_GROUPS
            and cleaned_comment != DEFAULT_GROUP
        ):
            whitelisted_comments.add(cleaned_comment)

    group_dict = {DEFAULT_GROUP: default_group_id}

    if whitelisted_comments:
        new_group_data = [
            (name, current_timestamp, current_timestamp, "")
            for name in sorted(whitelisted_comments)
        ]
        cursor.executemany(
            'INSERT INTO "group" (name, date_added, date_modified, description) '
            "VALUES (?, ?, ?, ?)",
            new_group_data,
        )

        cursor.execute(
            'SELECT id, name FROM "group" WHERE id != ?', (default_group_id,)
        )
        for group_id, name in cursor.fetchall():
            cleaned_name = clean_to_title_case(name)
            if cleaned_name:
                group_dict[cleaned_name] = group_id

        print(f"Successfully recreated {len(whitelisted_comments)} group(s).")

    return group_dict


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


def restore_client_mappings(
    cursor: sqlite3.Cursor,
    client_backup: Dict[int, List[str]],
    group_dict: Dict[str, int],
):
    """Re-links clients to the Default group and any newly recreated groups they belonged to."""
    default_group_id = group_dict[DEFAULT_GROUP]
    mapping_inserts = set()

    # 1. Guarantee every registered client is mapped to the Default group
    cursor.execute("SELECT id FROM client")
    for (client_id,) in cursor.fetchall():
        mapping_inserts.add((client_id, default_group_id))

    # 2. Restore previous mappings if the matched group was regenerated
    for client_id, group_names in client_backup.items():
        for group_name in group_names:
            cleaned_name = clean_to_title_case(group_name)
            if cleaned_name in group_dict and cleaned_name != DEFAULT_GROUP:
                mapping_inserts.add((client_id, group_dict[cleaned_name]))

    if mapping_inserts:
        cursor.executemany(
            "INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES (?, ?)",
            list(mapping_inserts),
        )
        # Find unique clients affected
        unique_clients = len(set(c[0] for c in mapping_inserts))
        print(
            f"Restored saved configurations and enforced Default fallback for {unique_clients} client(s)."
        )


def reload_pihole_engine():
    """Forces a full restart of the Pi-hole FTL container/service to guarantee a clean cache reload."""
    try:
        if os.path.exists("/.dockerenv"):
            subprocess.run(
                ["pkill", "-9", "-f", "pihole-FTL"],
                check=True,
                capture_output=True,
                text=True,
            )
        else:
            subprocess.run(
                ["docker", "restart", "pihole"],
                check=True,
                capture_output=True,
                text=True,
            )
        print("Successfully restarted Pi-hole engine and refreshed memory cache.")
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.strip() if e.stderr else e.stdout.strip()
        print(f"Warning: Failed to restart Pi-hole container. Details: {err_msg}")
    except Exception as e:
        print(f"Warning: Could not automatically restart Pi-hole FTL: {e}")


def push_to_github():
    """Commits and pushes whitelist.txt to GitHub autonomously using a mixed hex message."""
    repo_dir = WHITELIST_TXT_PATH.parent

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_AUTHOR_NAME"] = GIT_BOT_NAME
    env["GIT_AUTHOR_EMAIL"] = GIT_BOT_EMAIL
    env["GIT_COMMITTER_NAME"] = GIT_BOT_NAME
    env["GIT_COMMITTER_EMAIL"] = GIT_BOT_EMAIL

    try:
        subprocess.run(
            ["git", "add", "whitelist.txt"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )

        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )

        if not status.stdout.strip():
            print("No changes to whitelist.txt. Skipping GitHub push.")
            return

        commit_hex = generate_mixed_hex_comment(7)
        subprocess.run(
            ["git", "commit", "-m", commit_hex],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )

        subprocess.run(
            ["git", "pull", "--rebase", "origin", "main"],
            cwd=repo_dir,
            check=False,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )

        subprocess.run(
            ["git", "push"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
        print(
            f"Successfully pushed updated whitelist.txt to GitHub with commit message [{commit_hex}]."
        )

    except subprocess.TimeoutExpired as e:
        print(
            f"ERROR: Git operation timed out after {GIT_TIMEOUT_SECONDS}s: {' '.join(e.cmd)}"
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode("utf-8").strip() if e.stderr else "Unknown error"
        print(
            f"ERROR: Git operation failed during command: {' '.join(e.cmd)}\nDetails: {err_msg}"
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

        # 1. Capture Client State
        client_backup = backup_client_mappings(cursor)

        # 2. Rebuild Groups and Domain Mappings
        existing_groups = sync_groups(cursor)
        map_domains_to_groups(cursor, existing_groups)

        # 3. Restore Client State
        restore_client_mappings(cursor, client_backup, existing_groups)

        conn.commit()
        print(
            "Success: Database sync, entry migration, "
            "and file generation completed seamlessly."
        )

        # Force FTL to reload database changes
        reload_pihole_engine()

        # Push file to remote
        push_to_github()

    except Exception as e:
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
