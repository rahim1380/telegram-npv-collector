#!/usr/bin/env python3
"""Import .npvt files into a persistent, deduplicated config archive."""
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from npvt_decoder import decode_file

INPUT_DIR = Path("npvt_inputs")
TABLES_DIR = Path("npvt_tables")
ARCHIVE_PATH = Path("data/npvt_configs.json")
URI_RE = re.compile(r"""(?:vless|vmess|trojan|ss)://[^\s<>"']+""", re.IGNORECASE)


def load_archive():
    if not ARCHIVE_PATH.exists():
        return {}
    try:
        value = json.loads(ARCHIVE_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_PATH.parent.mkdir(parents=True, exist_ok=True)
    archive = load_archive()
    files = sorted(INPUT_DIR.glob("*.npvt"))
    imported = 0

    for path in files:
        try:
            records, errors, token_count = decode_file(path, TABLES_DIR, download_tables=True)
        except Exception as exc:
            print(f"[WARN] {path.name}: decode failed: {type(exc).__name__}: {exc}")
            continue

        file_added = 0
        for record in records:
            match = URI_RE.search(record.strip())
            if not match:
                continue
            config = match.group(0).rstrip(".,;)]}")
            if config not in archive:
                archive[config] = {
                    "source_file": path.name,
                    "imported_at": datetime.now(timezone.utc).isoformat()
                }
                imported += 1
                file_added += 1

        print(f"[INFO] {path.name}: {token_count} tokens, {file_added} new links, {len(errors)} token errors")

    ARCHIVE_PATH.write_text(json.dumps(archive, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[INFO] NPVT archive total: {len(archive)}; newly imported: {imported}")


if __name__ == "__main__":
    main()
