#!/usr/bin/env python3
import sqlite3
import sys
import logging
import re
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
    Removes illegal characters and trims whitespace.
    """
    sanitized = re.sub(r'[\\/*?:"<>|]', "", filename)
    sanitized = sanitized.strip().replace(" ", "_")
    return sanitized

def extract_whitelists(db_path: Path, output_dir: Path) -> None:
    """
    Connects to gravity.db, extracts exact whitelists, and writes them to files.
    """
    if not db_path.is_file():
        logger.error(f"Database file not found at {db_path}.")
        sys.exit(1)

    categories: Dict[str, List[str]] = {}
    
    try:
        logger.info(f"Connecting to database at {db_path}")
        # URI mode with ro (read-only) prevents accidental writes and handles locks better
        uri = f"file:{db_path.resolve()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            cursor = conn.cursor()
            
            # type = 0 represents Exact Whitelist in Pi-hole's domainlist table
            query = "SELECT domain, comment FROM domainlist WHERE type = 0"
            cursor.execute(query)
            
            for row in cursor.fetchall():
                domain, comment = row[0], row[1]
                
                # Normalize empty or whitespace-only comments to a consistent empty string
                if not comment or not comment.strip():
                    category_name = ""
                else:
                    category_name = comment.strip()
                
                if category_name not in categories:
                    categories[category_name] = []
                categories[category_name].append(domain)
                
    except sqlite3.Error as e:
        logger.error(f"Database error occurred: {e}")
        sys.exit(1)

    logger.info(f"Found {sum(len(domains) for domains in categories.values())} exact whitelist entries across {len(categories)} categories.")
    write_output_files(categories, output_dir)

def write_output_files(categories: Dict[str, List[str]], output_dir: Path) -> None:
    """
    Writes the categorized domains into separate text files using pathlib.
    """
    for comment, domains in categories.items():
        if not comment:
            # Empty comments append to whitelist.txt
            file_path = output_dir / "whitelist.txt"
            mode = "a"
            file_name_log = "whitelist.txt (appended)"
        else:
            # Named comments write to a fresh <Comment>.txt file
            safe_name = sanitize_filename(comment)
            file_path = output_dir / f"{safe_name}.txt"
            mode = "w"
            file_name_log = f"{safe_name}.txt (overwritten)"

        try:
            file_exists_and_not_empty = file_path.exists() and file_path.stat().st_size > 0

            with file_path.open(mode, encoding="utf-8") as f:
                # Start on a new line if appending to an existing file that already has content
                if mode == "a" and file_exists_and_not_empty:
                    f.write("\n")
                
                for domain in sorted(domains):
                    f.write(f"{domain}\n")
            
            logger.info(f"Saved {len(domains):<4} domains to {file_name_log}")
            
        except OSError as e:
            logger.error(f"Failed to write to {file_path}: {e}")

if __name__ == "__main__":
    current_dir = Path(__file__).parent.resolve()
    gravity_db = Path("/mnt/dietpi_userdata/docker/primary-stack/pihole/etc-pihole/gravity.db")
    
    extract_whitelists(gravity_db, current_dir)
    logger.info("Export completed successfully.")
