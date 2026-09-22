#!/usr/bin/env python3
import sqlite3
import sys
import logging
import re
import unicodedata
from pathlib import Path
from typing import Dict, List

# Configure production-grade logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes a string to be used as a valid, safe file name.
    """
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.strip().replace(" ", "_")
    return sanitized

def sanitize_domain(domain: str) -> str:
    """
    Fully sanitizes a domain entry by removing invisible unicode characters,
    zero-width spaces, control characters, trailing paths, and invalid domain chars.
    """
    if not domain:
        return ""
    
    # 1. Normalize Unicode
    domain = unicodedata.normalize("NFKC", domain)
    
    # 2. Filter out non-printable, control, and non-standard space characters
    domain = "".join(
        ch for ch in domain 
        if not unicodedata.category(ch).startswith("C") and unicodedata.category(ch) != "Zs"
    )
    
    # 3. Strip remaining outer whitespace and convert to lowercase
    domain = domain.strip().lower()
    
    # 4. Remove protocol prefixes if accidentally recorded
    domain = re.sub(r"^https?://", "", domain)
    
    # 5. Remove URI path, query params, or anchors
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    
    # 6. Remove invalid domain characters
    domain = re.sub(r"[^a-z0-9\.\-\_\*]", "", domain)
    
    # 7. Strip leading/trailing dots and hyphens
    domain = domain.strip(".-")
    
    return domain

def extract_whitelists(db_path: Path, output_dir: Path) -> None:
    """
    Connects to gravity.db, extracts exact whitelists, sanitizes entries, and writes them to files.
    """
    if not db_path.is_file():
        logger.error(f"Database file not found at {db_path}.")
        sys.exit(1)

    # Ensure the target "whitelists" directory exists
    output_dir.mkdir(parents=True, exist_ok=True)

    categories: Dict[str, List[str]] = {}
    
    try:
        logger.info(f"Connecting to database at {db_path}")
        uri = f"file:{db_path.resolve()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            cursor = conn.cursor()
            
            query = "SELECT domain, comment FROM domainlist WHERE type = 0"
            cursor.execute(query)
            
            for row in cursor.fetchall():
                raw_domain, comment = row[0], row[1]
                
                cleaned_domain = sanitize_domain(raw_domain)
                if not cleaned_domain:
                    logger.warning(f"Skipping empty/invalid domain entry after sanitization: '{raw_domain}'")
                    continue
                
                if not comment or not comment.strip():
                    category_name = ""
                else:
                    category_name = comment.strip()
                
                if category_name not in categories:
                    categories[category_name] = []
                categories[category_name].append(cleaned_domain)
                
    except sqlite3.Error as e:
        logger.error(f"Database error occurred: {e}")
        sys.exit(1)

    total_domains = sum(len(domains) for domains in categories.values())
    logger.info(f"Found {total_domains} valid exact whitelist entries across {len(categories)} categories.")
    write_output_files(categories, output_dir)

def write_output_files(categories: Dict[str, List[str]], output_dir: Path) -> None:
    """
    Writes the categorized domains into separate text files inside output_dir.
    Applies a frozenset for immutable deduplication, sorts alphabetically, 
    and always overwrites existing files.
    """
    for comment, domains in categories.items():
        if not comment:
            file_path = output_dir / "whitelist.txt"
            file_name_log = "whitelist.txt"
        else:
            safe_name = sanitize_filename(comment)
            file_path = output_dir / f"{safe_name}.txt"
            file_name_log = f"{safe_name}.txt"

        try:
            # Enforce strict deduplication using an immutable frozenset, 
            # then sort the results alphabetically into a list.
            unique_domains = sorted(frozenset(domains))

            # Always overwrite ("w") to ensure the file reflects the current database state exactly.
            with file_path.open("w", encoding="utf-8") as f:
                for domain in unique_domains:
                    f.write(f"{domain}\n")
            
            logger.info(f"Saved {len(unique_domains):<4} unique domain(s) to whitelists/{file_name_log} (overwritten)")
            
        except OSError as e:
            logger.error(f"Failed to write to {file_path}: {e}")

if __name__ == "__main__":
    current_dir = Path(__file__).parent.resolve()
    whitelists_dir = current_dir / "whitelists"
    gravity_db = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    
    extract_whitelists(gravity_db, whitelists_dir)
    logger.info("Export completed successfully.")
