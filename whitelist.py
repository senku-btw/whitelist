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
        ch
        for ch in domain
        if not unicodedata.category(ch).startswith("C")
        and unicodedata.category(ch) != "Zs"
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
    Ignores entries that have no comment or have a comment starting with '#'.
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

                category_name = comment.strip()

                # Filter: Exclude entries with no comment or comments starting with '#'
                if not category_name or category_name.startswith("#"):
                    continue

                cleaned_domain = sanitize_domain(raw_domain)
                if not cleaned_domain:
                    continue

                if category_name not in categories:
                    categories[category_name] = set()
                categories[category_name].add(cleaned_domain)

    except sqlite3.Error:
        sys.exit(1)

    return categories


def _merge_existing_immutables(target_dir: Path, categories: Dict[str, Set[str]]) -> None:
    """
    Merges existing file entries from target_dir for specific immutable categories.
    This ensures these categories are append-only.
    """
    immutable_categories = ["hosts", "Facebook"]

    for category in immutable_categories:
        file_name = f"{sanitize_filename(category)}.txt"
        file_path = target_dir / file_name

        if not file_path.is_file():
            continue

        if category not in categories:
            categories[category] = set()

        try:
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line:
                        categories[category].add(clean_line)
        except OSError:
            pass


def _write_category_files(categories: Dict[str, Set[str]], tmp_dir: Path) -> None:
    """
    Writes categorized domains to individual text files in the temporary directory.
    """
    for comment, domains in categories.items():
        file_name = f"{sanitize_filename(comment)}.txt"
        file_path = tmp_dir / file_name

        unique_domains = sorted(frozenset(domains))

        with file_path.open("w", encoding="utf-8", newline="\n") as f:
            for domain in unique_domains:
                f.write(f"{domain}\n")


def write_whitelists_atomically(
    categories: Dict[str, Set[str]], target_dir: Path
) -> None:
    """
    Performs a true atomic directory swap to guarantee filesystem integrity.
    Merges existing files for immutable categories to ensure append-only behavior.
    """
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

    except OSError:
        if backup_dir.exists() and not target_dir.exists():
            backup_dir.rename(target_dir)
        sys.exit(1)

    finally:
        for cleanup_dir in (tmp_dir, backup_dir):
            if cleanup_dir.exists():
                shutil.rmtree(cleanup_dir, ignore_errors=True)


def git_sync(repo_dir: Path) -> None:
    """
    Pulls upstream changes, stages all changes, and pushes via a random 7-character hex ID.
    Enforces strict subprocess timeouts to prevent environment lockups.
    """
    if not (repo_dir / ".git").is_dir():
        sys.exit(1)

    # Self-heal stale lock files left by interrupted executions
    index_lock = repo_dir / ".git" / "index.lock"
    if index_lock.is_file():
        try:
            index_lock.unlink()
        except OSError:
            pass

    try:
        # Pull upstream changes to prevent push conflicts
        subprocess.run(
            ["git", "pull", "--rebase", "--autostash"],
            cwd=repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30.0,
        )

        subprocess.run(
            ["git", "add", "-A"],
            cwd=repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30.0,
        )

        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            check=True,
            timeout=30.0,
        )

        if status.stdout.strip():
            commit_message = secrets.token_hex(4)[:7]

            subprocess.run(
                ["git", "commit", "-m", commit_message],
                cwd=repo_dir,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30.0,
            )
            subprocess.run(
                ["git", "push"],
                cwd=repo_dir,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30.0,
            )

    except (subprocess.SubprocessError, OSError):
        sys.exit(1)


def main() -> None:
    """
    Main execution entry point.
    """
    try:
        current_dir = Path(__file__).parent.resolve()
        whitelists_dir = current_dir / "whitelists"
        gravity_db = Path(
            "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"
        )

        categories = read_db_whitelists(gravity_db)
        write_whitelists_atomically(categories, whitelists_dir)
        git_sync(current_dir)

    except Exception:  # pylint: disable=broad-exception-caught
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
