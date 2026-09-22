"""
Automated Pi-hole exact whitelist extractor and Git synchronization script.

Reads whitelist entries from gravity.db, sanitizes domain names, categorizes them
by comment into individual files, and commits structural changes to Git.
"""

import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path
from typing import Dict, Set


def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a string to be used as a safe filesystem name.
    """
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.strip().replace(" ", "_")
    return sanitized if sanitized else "unnamed_category"


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


def read_db_whitelists(db_path: Path) -> Dict[str, Set[str]]:
    """
    Reads exact whitelists (type = 0) from gravity.db with timeout and read-only URI parameters.
    """
    if not db_path.is_file():
        raise FileNotFoundError(f"Database file missing: {db_path}")

    categories: Dict[str, Set[str]] = {}

    # 30-second connection timeout handles transient SQLite database locks from Pi-hole/FTL
    uri = f"file:{db_path.resolve()}?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=30.0) as conn:
        cursor = conn.cursor()
        query = "SELECT domain, comment FROM domainlist WHERE type = 0"
        cursor.execute(query)

        for raw_domain, comment in cursor.fetchall():
            cleaned_domain = sanitize_domain(raw_domain or "")
            if not cleaned_domain:
                continue

            category_name = comment.strip() if comment and comment.strip() else ""

            if category_name not in categories:
                categories[category_name] = set()
            categories[category_name].add(cleaned_domain)

    return categories


def write_whitelists_atomically(categories: Dict[str, Set[str]], target_dir: Path) -> None:
    """
    Writes output into a staging directory first, then atomically replaces target_dir.
    Guarantees the filesystem state is never left incomplete if an abort occurs.
    The 'hosts' category is strictly preserved and only appended to.
    """
    target_dir.mkdir(parents=True, exist_ok=True)

    # Immutability policy for "hosts": Merge existing entries from disk into memory
    # so they survive the atomic directory swap, ensuring it acts as an append-only file.
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
            sys.exit(1)

    # Create temp directory on the same mount point to allow atomic operations
    with tempfile.TemporaryDirectory(
        dir=target_dir.parent, prefix=".whitelists_tmp_"
    ) as tmp_dir_str:
        tmp_dir = Path(tmp_dir_str)

        for comment, domains in categories.items():
            file_name = "whitelist.txt" if not comment else f"{sanitize_filename(comment)}.txt"
            file_path = tmp_dir / file_name

            # Enforce immutable deduplication and alphabetical sorting
            unique_domains = sorted(frozenset(domains))

            with file_path.open("w", encoding="utf-8", newline="\n") as f:
                for domain in unique_domains:
                    f.write(f"{domain}\n")

        # Atomic directory swap
        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.copytree(tmp_dir, target_dir)


def git_sync(repo_dir: Path) -> None:
    """
    Stages all changes, verifies structural/file modifications,
    and commits/pushes using a 7-character random hex ID.
    """
    # Self-heal stale lock files left by interrupted executions
    index_lock = repo_dir / ".git" / "index.lock"
    if index_lock.is_file():
        try:
            index_lock.unlink()
        except OSError:
            pass

    # Stage all filesystem modifications
    subprocess.run(
        ["git", "add", "-A"],
        cwd=repo_dir,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Check status for changes
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        check=True
    )

    # Commit and push only if structural or content differences exist
    if status.stdout.strip():
        # Generate a random 7-character hex string to simulate a commit hash ID
        commit_message = secrets.token_hex(4)[:7]

        subprocess.run(
            ["git", "commit", "-m", commit_message],
            cwd=repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        subprocess.run(
            ["git", "push"],
            cwd=repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )


def main() -> None:
    """
    Main execution workflow for Pi-hole whitelist export and Git sync.
    """
    try:
        current_dir = Path(__file__).parent.resolve()
        whitelists_dir = current_dir / "whitelists"
        gravity_db = Path(
            "/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db"
        )

        # 1. Read & sanitize DB entries
        categories = read_db_whitelists(gravity_db)

        # 2. Atomically mirror to whitelists directory (with hosts file preservation)
        write_whitelists_atomically(categories, whitelists_dir)

        # 3. Synchronize with Git repository
        git_sync(current_dir)

    except (sqlite3.Error, OSError, subprocess.SubprocessError):
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
