import sqlite3
import re
import time
import sys
import fcntl
from pathlib import Path
from types import MappingProxyType

# Define paths
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
LOCK_FILE_PATH = Path("/tmp/pihole_group_sync.lock")

# Define immutable set of groups to skip
SKIPPED_GROUPS = frozenset([
    "Hosts"
])

# Define the mandatory first group that must never be deleted
DEFAULT_GROUP = "Default"

# Define exact replacements for legacy corrupted data
CORRECTIONS = MappingProxyType({
    "Microsoftoffice": "Microsoft Office",
    "Microsoftoutlook": "Microsoft Outlook",
    "Amazonkindle": "Amazon Kindle"
})

def clean_to_title_case(text: str) -> str:
    """Sanitize control chars, normalize whitespace, apply corrections, and Title Case."""
    if not text:
        return ""
    
    # Remove invisible control/null characters
    clean = re.sub(r'[\x00-\x1f\x7f]+', '', str(text))
    
    # Normalize whitespace and strip edges
    clean = re.sub(r'\s+', ' ', clean).strip().title()
    
    # Forcefully correct legacy concatenated words
    if clean in CORRECTIONS:
        return CORRECTIONS[clean]
        
    return clean

def main():
    # -------------------------------------------------------------
    # Single-Instance Enforcement via File Locking
    # -------------------------------------------------------------
    lock_file = open(LOCK_FILE_PATH, "w")
    try:
        # Try to acquire a non-blocking exclusive lock
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except IOError:
        print("ERROR: Another instance of this script is already running. Exiting.")
        sys.exit(1)

    if not DB_PATH.exists():
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        # -------------------------------------------------------------
        # PART 1: Group Synchronization & Auto-Creation
        # -------------------------------------------------------------
        
        # 1. Fetch existing groups from the database
        cursor.execute('SELECT id, name FROM "group"')
        existing_groups_raw = cursor.fetchall()

        # Map existing names (cleaned) to their IDs
        existing_group_dict = {}
        for group_id, name in existing_groups_raw:
            cleaned_name = clean_to_title_case(name)
            if cleaned_name:
                existing_group_dict[cleaned_name] = group_id

        # 2. Ensure "Default" group exists in the database. If missing, insert it.
        current_timestamp = int(time.time())
        if DEFAULT_GROUP not in existing_group_dict:
            cursor.execute(
                'INSERT INTO "group" (name, date_added, date_modified, description) VALUES (?, ?, ?, ?)',
                (DEFAULT_GROUP, current_timestamp, current_timestamp, "")
            )
            existing_group_dict[DEFAULT_GROUP] = cursor.lastrowid
            print(f"Created missing '{DEFAULT_GROUP}' group.")

        # 3. Fetch comments from exact whitelisted entries (type = 0)
        cursor.execute("SELECT comment FROM domainlist WHERE type = 0 AND comment IS NOT NULL AND comment != ''")
        comments_raw = cursor.fetchall()

        # Extract unique, sanitized whitelist comments
        whitelisted_comments = set()
        for row in comments_raw:
            cleaned_comment = clean_to_title_case(row[0])
            if cleaned_comment and cleaned_comment not in SKIPPED_GROUPS:
                whitelisted_comments.add(cleaned_comment)

        # 4. Determine new groups to add (comments that aren't already groups)
        existing_names_set = set(existing_group_dict.keys())
        new_groups = whitelisted_comments - existing_names_set

        print(f"Identified {len(existing_names_set)} existing valid groups.")
        print(f"Identified {len(new_groups)} new groups to add from whitelist comments.")

        # 5. Insert new groups non-destructively
        if new_groups:
            new_group_data = [
                (name, current_timestamp, current_timestamp, "") 
                for name in sorted(new_groups)
            ]
            cursor.executemany(
                'INSERT INTO "group" (name, date_added, date_modified, description) VALUES (?, ?, ?, ?)',
                new_group_data
            )
            
            # Refresh the dictionary to include the newly inserted group IDs
            cursor.execute('SELECT id, name FROM "group"')
            for group_id, name in cursor.fetchall():
                cleaned_name = clean_to_title_case(name)
                if cleaned_name:
                    existing_group_dict[cleaned_name] = group_id
                    
            print(f"Successfully inserted {len(new_groups)} new group(s).")

        # -------------------------------------------------------------
        # PART 2: Domain-to-Group Comment Mapping
        # -------------------------------------------------------------
        
        # 6. Fetch all exact whitelist entries with comments
        cursor.execute('SELECT id, comment FROM domainlist WHERE type = 0 AND comment IS NOT NULL AND comment != ""')
        domains_raw = cursor.fetchall()

        mapping_inserts = []
        for domain_id, comment in domains_raw:
            cleaned_comment = clean_to_title_case(comment)
            # If the comment corresponds to a valid managed group, map it
            if cleaned_comment and cleaned_comment in existing_group_dict:
                group_id = existing_group_dict[cleaned_comment]
                mapping_inserts.append((domain_id, group_id))

        if mapping_inserts:
            # Use INSERT OR IGNORE to safely skip relations that already exist
            cursor.executemany(
                'INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES (?, ?)',
                mapping_inserts
            )
            print(f"Successfully linked {len(mapping_inserts)} whitelist domain(s) to their corresponding groups.")

        conn.commit()
        print("Success: Database sync and domain-group linking completed seamlessly.")

    except Exception as e:
        conn.rollback()
        print(f"FATAL ERROR: Operation failed. Rolled back database changes.\nDetails: {e}")
    finally:
        conn.close()
        # Release the lock file handle automatically upon exit
        lock_file.close()

if __name__ == "__main__":
    main()
