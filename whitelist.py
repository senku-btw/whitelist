"""
Combined Autonomous Pi-hole Group Manager, Whitelist Pipeline, and Git Sync.

Executes a unified pipeline:
1. Migrates '#' comment domains from gravity.db into whitelist.txt, preserving
   category comment order while sorting domains within each category.
2. Rebuilds Pi-hole groups based on regular domain comments (min 2 occurrences)
   and maps domains/clients, ignoring default web query log entries.
3. Extracts categorized whitelists from gravity.db into individual files under whitelists/.
4. Reloads Pi-hole FTL and pushes all changes to Git.
"""

import fcntl
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import time
import unicodedata
from collections import defaultdict
from pathlib import Path
from types import MappingProxyType
from typing import Dict, List, Set

# --- Path Configurations ---
SCRIPT_DIR = Path(__file__).parent.resolve()
DB_PATH = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
LOCK_FILE_PATH = Path("/tmp/pihole_group_sync.lock")
WHITELIST_TXT_PATH = SCRIPT_DIR / "whitelist.txt"
WHITELISTS_DIR = SCRIPT_DIR / "whitelists"

# --- Group & Whitelist Rules ---
SKIPPED_GROUPS = frozenset(["Hosts"])
DEFAULT_GROUP = "Default"
MIN_GROUP_OCCURRENCES = 2
IMMUTABLE_CATEGORIES = frozenset(["hosts", "Facebook"])
IGNORED_COMMENT_SUBSTRINGS = (
    "added through the query log",
    "added from query log",
)

CORRECTIONS = MappingProxyType(
    {
        "Microsoftoffice": "Microsoft Office",
        "Microsoftoutlook": "Microsoft Outlook",
        "Amazonkindle": "Amazon Kindle",
    }
)

# --- Git Configurations ---
GIT_BOT_NAME = "Pi-hole Auto Sync Bot"
GIT_BOT_EMAIL = "pihole-bot@users.noreply.github.com"
GIT_TIMEOUT_SECONDS = 30


# ==============================================================================
# Helper Utilities & Sanitization
# ==============================================================================


def generate_mixed_hex_comment(length: int = 7) -> str:
    """Generates a random hex string containing both digits and letters (a-f)."""
    while True:
        token = secrets.token_hex(4)[:length]
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            return token


def sanitize_filename(filename: str) -> str:
    """Sanitizes a string to be used as a safe filesystem name."""
    if not isinstance(filename, str):
        return "unnamed_category"

    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.strip().replace(" ", "_")
    return sanitized if sanitized else "unnamed_category"


def sanitize_domain(domain: str) -> str:
    """
    Fully sanitizes a domain entry by normalizing Unicode, removing control/space
    characters, stripping protocols/paths, and enforcing standard domain chars.
    """
    if not domain or not isinstance(domain, str):
        return ""

    domain = unicodedata.normalize("NFKC", domain)
    domain = "".join(
        ch
        for ch in domain
        if not unicodedata.category(ch).startswith("C")
        and unicodedata.category(ch) != "Zs"
    )
    domain = domain.strip().lower()
    domain = re.sub(r"^https?://", "", domain)
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    domain = re.sub(r"[^a-z0-9\.\-\_\*]", "", domain)
    return domain.strip(".-")


def clean_to_title_case(text: str) -> str:
    """Sanitize control chars, normalize whitespace, apply corrections, and Title Case,
    preserving exact letter casing inside parentheses."""
    if not text:
        return ""
    clean = re.sub(r"[\x00-\x1f\x7f]+", "", str(text))
    clean = re.sub(r"\s+", " ", clean).strip()
    if not clean:
        return ""

    # Split string by parenthetical sections: e.g. "category (VSCs)" -> ["category ", "(VSCs)", ""]
    parts = re.split(r"(\([^\)]*\))", clean)
    processed = []
    for part in parts:
        if part.startswith("(") and part.endswith(")"):
            processed.append(part)
        else:
            processed.append(part.title())

    result = "".join(processed)
    if result in CORRECTIONS:
        return CORRECTIONS[result]
    return result


def split_comment_into_groups(comment: str) -> List[str]:
    """
    Splits a comment string into individual group names when separated by delimiters
    like '/', ',', ';', ' & ', or ' and ' (e.g. 'Microsoft Windows/Spotify'),
    while preserving multi-word group names and text inside parentheses.
    """
    if not comment:
        return []

    # Isolate parenthetical blocks so delimiters inside parentheses aren't split
    parts = re.split(r"(\([^\)]*\))", comment)
    delim_pattern = re.compile(r"\s*(?:/|,|;|\s+&\s+|\s+and\s+)\s*", re.IGNORECASE)

    groups = [""]
    for part in parts:
        if part.startswith("(") and part.endswith(")"):
            groups[-1] += part
        else:
            subparts = delim_pattern.split(part)
            groups[-1] += subparts[0]
            for sub in subparts[1:]:
                groups.append(sub)

    cleaned_groups = [g.strip() for g in groups if g.strip()]
    return cleaned_groups if cleaned_groups else [comment.strip()]


def is_valid_domain(domain: str) -> bool:
    """Checks if a string is a valid, pure domain name."""
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip()
    if len(domain) > 253:
        return False

    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )
    return bool(pattern.match(domain))


def is_ignored_comment(comment: str) -> bool:
    """Checks if a comment matches default web interface patterns that should be skipped."""
    if not comment:
        return False
    lowered = comment.strip().lower()
    return any(sub in lowered for sub in IGNORED_COMMENT_SUBSTRINGS)


# ==============================================================================
# Part 1: Whitelist.txt and Group Management Operations
# ==============================================================================


def parse_whitelist_file() -> Dict[str, Set[str]]:
    """
    Parses whitelist.txt into a dict mapping category comments to sets of domains,
    preserving the original order in which category headers appear.
    """
    merged_data: Dict[str, Set[str]] = {}
    current_comment = None

    if WHITELIST_TXT_PATH.exists():
        with open(WHITELIST_TXT_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#"):
                    raw_comment = line.lstrip("#").strip()
                    formatted_comment = clean_to_title_case(raw_comment)
                    current_comment = f"# {formatted_comment}"
                    if current_comment not in merged_data:
                        merged_data[current_comment] = set()
                elif current_comment:
                    sanitized = sanitize_domain(line)
                    if is_valid_domain(sanitized):
                        merged_data[current_comment].add(sanitized)

    return merged_data


def _write_whitelist_file(cleaned_whitelist: Dict[str, List[str]]) -> None:
    """Helper to write formatted whitelist categories and domains to whitelist.txt."""
    with open(WHITELIST_TXT_PATH, "w", encoding="utf-8") as f:
        for cat_comment, doms in cleaned_whitelist.items():
            f.write(f"{cat_comment}\n")
            for dom in doms:
                f.write(f"{dom}\n")
            f.write("\n")


def process_and_clean_whitelist(cursor: sqlite3.Cursor) -> List[int]:
    """
    Parses whitelist.txt and gravity.db '#' entries, recreates whitelist.txt
    preserving category order and sorting domains under each category.
    Allows domains to exist across multiple categories without pruning.
    """
    merged_data = parse_whitelist_file()

    cursor.execute(
        "SELECT id, domain, comment FROM domainlist "
        "WHERE type = 0 AND comment LIKE '#%'"
    )

    db_ids_to_delete = []
    for domain_id, domain, comment in cursor.fetchall():
        clean_dom = sanitize_domain(domain)
        if is_valid_domain(clean_dom):
            for cat in split_comment_into_groups(comment.lstrip("#").strip()):
                clean_cmt = f"# {clean_to_title_case(cat)}"
                merged_data.setdefault(clean_cmt, set()).add(clean_dom)
            db_ids_to_delete.append(domain_id)

    cleaned_whitelist = {
        cat: sorted([d for d in doms if is_valid_domain(d)])
        for cat, doms in merged_data.items()
        if any(is_valid_domain(d) for d in doms)
    }

    _write_whitelist_file(cleaned_whitelist)
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
    """Records current client-to-group configurations before database purge."""
    cursor.execute(
        """
        SELECT cbg.client_id, g.name
        FROM client_by_group cbg
        JOIN "group" g ON cbg.group_id = g.id
        """
    )
    client_backup: Dict[int, List[str]] = defaultdict(list)
    for client_id, group_name in cursor.fetchall():
        client_backup[client_id].append(group_name)

    return dict(client_backup)


def sync_groups(cursor: sqlite3.Cursor) -> Dict[str, int]:
    """
    Purges non-Default groups and mappings, recreates missing groups based on
    whitelist comments that appear at least MIN_GROUP_OCCURRENCES times,
    and returns a mapping of group names to IDs.
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

    cursor.execute(
        "DELETE FROM domainlist_by_group WHERE group_id != ?", (default_group_id,)
    )
    cursor.execute(
        "DELETE FROM client_by_group WHERE group_id != ?", (default_group_id,)
    )
    cursor.execute(
        "DELETE FROM adlist_by_group WHERE group_id != ?", (default_group_id,)
    )

    cursor.execute('DELETE FROM "group" WHERE id != ?', (default_group_id,))
    print("Purged all previous non-Default groups and associated mappings.")

    cursor.execute(
        "SELECT comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    )

    comment_counts: Dict[str, int] = defaultdict(int)
    for row in cursor.fetchall():
        raw_comment = row[0].strip()
        if raw_comment.startswith("#") or is_ignored_comment(raw_comment):
            continue

        for cat in split_comment_into_groups(raw_comment):
            cleaned_comment = clean_to_title_case(cat)
            if (
                cleaned_comment
                and cleaned_comment not in SKIPPED_GROUPS
                and cleaned_comment != DEFAULT_GROUP
            ):
                comment_counts[cleaned_comment] += 1

    whitelisted_comments = {
        comment
        for comment, count in comment_counts.items()
        if count >= MIN_GROUP_OCCURRENCES
    }

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

        print(
            f"Successfully recreated {len(whitelisted_comments)} group(s) "
            f"(met threshold of {MIN_GROUP_OCCURRENCES}+ occurrences)."
        )

    return group_dict


def map_domains_to_groups(cursor: sqlite3.Cursor, group_dict: Dict[str, int]):
    """Maps domains to all corresponding groups based on whitelist comments."""
    cursor.execute(
        "SELECT id, comment FROM domainlist "
        "WHERE type = 0 AND comment IS NOT NULL AND comment != ''"
    )

    domains_to_clear = []
    mapping_inserts = []
    default_group_id = group_dict[DEFAULT_GROUP]

    for domain_id, comment in cursor.fetchall():
        raw_comment = comment.strip()
        if raw_comment.startswith("#") or is_ignored_comment(raw_comment):
            continue

        domains_to_clear.append((domain_id,))

        matched_any = False
        for cat in split_comment_into_groups(raw_comment):
            cleaned_comment = clean_to_title_case(cat)
            if cleaned_comment and cleaned_comment in group_dict:
                group_id = group_dict[cleaned_comment]
                mapping_inserts.append((domain_id, group_id))
                matched_any = True

        if not matched_any:
            mapping_inserts.append((domain_id, default_group_id))

    if domains_to_clear:
        cursor.executemany(
            "DELETE FROM domainlist_by_group WHERE domainlist_id = ?",
            domains_to_clear,
        )

    if mapping_inserts:
        cursor.executemany(
            "INSERT INTO domainlist_by_group (domainlist_id, group_id) "
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
    """Re-links clients to Default group and any newly recreated matching groups."""
    default_group_id = group_dict[DEFAULT_GROUP]
    mapping_inserts = set()

    cursor.execute("SELECT id FROM client")
    for (client_id,) in cursor.fetchall():
        mapping_inserts.add((client_id, default_group_id))

    for client_id, group_names in client_backup.items():
        for group_name in group_names:
            cleaned_name = clean_to_title_case(group_name)
            if cleaned_name in group_dict and cleaned_name != DEFAULT_GROUP:
                mapping_inserts.add((client_id, group_dict[cleaned_name]))

    if mapping_inserts:
        cursor.executemany(
            "INSERT OR IGNORE INTO client_by_group (client_id, group_id) "
            "VALUES (?, ?)",
            list(mapping_inserts),
        )
        unique_clients = len(set(c[0] for c in mapping_inserts))
        print(
            "Restored saved configurations and enforced Default fallback "
            f"for {unique_clients} client(s)."
        )


# ==============================================================================
# Part 2: Categorized Whitelist File Extraction (Adapted for Subcategories)
# ==============================================================================


def read_db_whitelists(db_path: Path) -> Dict[str, Dict[str, Set[str]]]:
    """Reads whitelists (type = 0) grouped by category and optional bracketed subcategories."""
    if not db_path.is_file():
        return {}

    # Structure: categories[Main_Category][Sub_Category] = {domains...}
    categories: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(set))
    uri = f"file:{db_path.resolve()}?mode=ro"

    try:
        with sqlite3.connect(uri, uri=True, timeout=30.0) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain, comment FROM domainlist WHERE type = 0")

            for row in cursor.fetchall():
                raw_domain = row[0] if row[0] is not None else ""
                comment = row[1] if row[1] is not None else ""
                category_name = comment.strip()

                if (
                    not category_name
                    or category_name.startswith("#")
                    or is_ignored_comment(category_name)
                ):
                    continue

                cleaned_domain = sanitize_domain(raw_domain)
                if not cleaned_domain or not is_valid_domain(cleaned_domain):
                    continue

                for cat in split_comment_into_groups(category_name):
                    # Extract bracketed subcategories (matches both [] and {})
                    match = re.search(r'^(.*?)\s*[\[\{](.*?)[\]\}]\s*$', cat)
                    if match:
                        main_cat = clean_to_title_case(match.group(1))
                        sub_cat = clean_to_title_case(match.group(2))
                    else:
                        main_cat = clean_to_title_case(cat)
                        sub_cat = ""

                    if not main_cat:
                        continue

                    categories[main_cat][sub_cat].add(cleaned_domain)

    except sqlite3.Error as e:
        print(f"Error reading gravity.db for file extraction: {e}")

    return categories


def _merge_existing_immutables(
    target_dir: Path, categories: Dict[str, Dict[str, Set[str]]]
) -> None:
    """Ensures specified categories are append-only by merging existing directory files."""
    for category in IMMUTABLE_CATEGORIES:
        file_name = f"{sanitize_filename(category)}.txt"
        file_path = target_dir / file_name

        if not file_path.is_file():
            continue

        try:
            with file_path.open("r", encoding="utf-8") as f:
                current_sub = ""
                for line in f:
                    line = line.strip()
                    if line.startswith("#"):
                        current_sub = line.lstrip("#").strip()
                        continue

                    clean_line = sanitize_domain(line)
                    if is_valid_domain(clean_line):
                        categories[category][current_sub].add(clean_line)
        except OSError:
            pass


def _write_category_files(categories: Dict[str, Dict[str, Set[str]]], tmp_dir: Path) -> None:
    """Writes categorized domains and their subcategories to individual text files."""
    for category, subcategories in categories.items():
        file_name = f"{sanitize_filename(category)}.txt"
        file_path = tmp_dir / file_name

        # Check if the category has any valid domains across all subcategories
        has_domains = any(
            is_valid_domain(sanitize_domain(d))
            for doms in subcategories.values()
            for d in doms
        )
        if not has_domains:
            continue

        with file_path.open("w", encoding="utf-8", newline="\n") as f:
            # 1. Base group domains (no subcategory comment)
            if "" in subcategories:
                sanitized_base_set = {
                    sanitize_domain(d)
                    for d in subcategories[""]
                    if is_valid_domain(sanitize_domain(d))
                }
                base_domains = sorted(sanitized_base_set)

                for domain in base_domains:
                    f.write(f"{domain}\n")
                if base_domains and len(subcategories) > 1:
                    f.write("\n")

            # 2. Subcategories (alphabetized)
            for subcat in sorted(k for k in subcategories.keys() if k):
                sanitized_subcat_set = {
                    sanitize_domain(d)
                    for d in subcategories[subcat]
                    if is_valid_domain(sanitize_domain(d))
                }
                subcat_domains = sorted(sanitized_subcat_set)

                if subcat_domains:
                    f.write(f"# {subcat}\n")
                    for domain in subcat_domains:
                        f.write(f"{domain}\n")
                    f.write("\n")


def write_whitelists_atomically(
    categories: Dict[str, Dict[str, Set[str]]], target_dir: Path
) -> None:
    """Atomically swaps directory contents with freshly exported category text files."""
    target_dir.parent.mkdir(parents=True, exist_ok=True)
    _merge_existing_immutables(target_dir, categories)

    hex_id = secrets.token_hex(4)
    tmp_dir = target_dir.with_name(f".{target_dir.name}_tmp_{hex_id}")
    backup_dir = target_dir.with_name(f".{target_dir.name}_backup_{hex_id}")

    try:
        tmp_dir.mkdir(parents=True, exist_ok=True)
        _write_category_files(categories, tmp_dir)

        if target_dir.exists():
            target_dir.rename(backup_dir)

        tmp_dir.rename(target_dir)
        print(
            f"Successfully updated individual whitelist files in '{target_dir.name}/'."
        )

    except OSError as e:
        print(f"Failed atomic write for category files: {e}")
        if backup_dir.exists() and not target_dir.exists():
            backup_dir.rename(target_dir)
        raise

    finally:
        for cleanup_dir in (tmp_dir, backup_dir):
            if cleanup_dir.exists():
                shutil.rmtree(cleanup_dir, ignore_errors=True)


# ==============================================================================
# Part 3: Engine Reload & Git Synchronization
# ==============================================================================


def reload_pihole_engine():
    """Forces a full restart/refresh of Pi-hole FTL engine to reload memory cache."""
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
    except (OSError, subprocess.SubprocessError) as e:
        print(f"Warning: Could not automatically restart Pi-hole FTL: {e}")


def git_sync(repo_dir: Path) -> None:
    """Stages all changes, commits with a mixed hex ID, and pushes upstream."""
    if not (repo_dir / ".git").is_dir():
        print(f"Error: {repo_dir} is not a Git repository.")
        return

    index_lock = repo_dir / ".git" / "index.lock"
    if index_lock.is_file():
        try:
            index_lock.unlink()
        except OSError:
            pass

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_AUTHOR_NAME"] = GIT_BOT_NAME
    env["GIT_AUTHOR_EMAIL"] = GIT_BOT_EMAIL
    env["GIT_COMMITTER_NAME"] = GIT_BOT_NAME
    env["GIT_COMMITTER_EMAIL"] = GIT_BOT_EMAIL

    try:
        subprocess.run(
            ["git", "pull", "--rebase", "--autostash"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )

        subprocess.run(
            ["git", "add", "-A"],
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
            print("No repository changes detected. Skipping Git push.")
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
            ["git", "push"],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=GIT_TIMEOUT_SECONDS,
            env=env,
        )
        print(f"Successfully pushed all changes to Git [commit: {commit_hex}].")

    except subprocess.TimeoutExpired as e:
        print(
            f"ERROR: Git operation timed out after {GIT_TIMEOUT_SECONDS}s: {' '.join(e.cmd)}"
        )
    except subprocess.CalledProcessError as e:
        err_msg = e.stderr.decode("utf-8").strip() if e.stderr else "Unknown error"
        print(f"ERROR: Git operation failed: {' '.join(e.cmd)}\nDetails: {err_msg}")


# ==============================================================================
# Core Pipeline Execution & Main Entry Point
# ==============================================================================


def run_sync_pipeline():
    """Executes the full combined pipeline."""
    if not DB_PATH.exists():
        print(f"FATAL: Database not found at {DB_PATH}")
        sys.exit(1)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        conn.execute("BEGIN TRANSACTION")

        print(f"Processing and regenerating {WHITELIST_TXT_PATH.name}...")
        ids_to_delete = process_and_clean_whitelist(cursor)
        remove_migrated_domains(cursor, ids_to_delete)

        client_backup = backup_client_mappings(cursor)
        existing_groups = sync_groups(cursor)
        map_domains_to_groups(cursor, existing_groups)
        restore_client_mappings(cursor, client_backup, existing_groups)

        conn.commit()
        print("Database transaction committed successfully.")

    except Exception as e:  # pylint: disable=broad-exception-caught
        conn.rollback()
        print(
            f"FATAL ERROR: Operation failed. Rolled back database changes.\nDetails: {e}"
        )
        sys.exit(1)
    finally:
        conn.close()

    categories = read_db_whitelists(DB_PATH)
    write_whitelists_atomically(categories, WHITELISTS_DIR)

    reload_pihole_engine()

    git_sync(SCRIPT_DIR)


def main():
    """Main entry point enforcing single-instance execution via lockfile."""
    try:
        with open(LOCK_FILE_PATH, "w", encoding="utf-8") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                print("ERROR: Another instance of this script is already running.")
                sys.exit(1)

            run_sync_pipeline()

    except OSError as err:
        print(f"Failed to open or lock file: {err}")
        sys.exit(1)


if __name__ == "__main__":
    main()
