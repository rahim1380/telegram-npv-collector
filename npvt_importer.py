import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from npvt_decoder import decode_file

INPUT_DIR = Path("npvt_inputs")
TABLES_DIR = Path("npvt_tables")

ARCHIVE_PATH = Path("data/npvt_configs.json")
STATE_PATH = Path("data/npvt_telegram_state.json")
RECENT_PATH = Path("data/npvt_recent_configs.json")

RECENT_HOURS = 24

URI_RE = re.compile(
    r"""(?:vless|vmess|trojan|ss)://[^\s<>"']+""",
    re.IGNORECASE
)


def load_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value
    except (OSError, json.JSONDecodeError):
        return default


def parse_date(value):
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc)
    except ValueError:
        return None


def main():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    ARCHIVE_PATH.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=RECENT_HOURS)

    archive = load_json(ARCHIVE_PATH, {})
    if not isinstance(archive, dict):
        archive = {}

    state = load_json(STATE_PATH, {})
    if not isinstance(state, dict):
        state = {}

    recent_events = state.get("recent_downloads", [])
    if not isinstance(recent_events, list):
        recent_events = []

    # Map each recently published NPVT file to its publication date.
    recent_files = {}

    for event in recent_events:
        if not isinstance(event, dict):
            continue

        published_at = parse_date(event.get("published_at"))
        filename = event.get("file")

        if not filename or not published_at:
            continue

        if not (cutoff <= published_at <= now):
            continue

        previous = recent_files.get(filename)
        if previous is None or published_at > previous:
            recent_files[filename] = published_at

    recent_archive = {}
    imported = 0
    decoded_files = 0

    for path in sorted(INPUT_DIR.glob("*.npvt")):
        try:
            records, errors, token_count = decode_file(
                path,
                TABLES_DIR,
                download_tables=True
            )
        except Exception as exc:
            print(
                f"[WARN] {path.name}: decode failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        decoded_files += 1
        file_added = 0
        published_at = recent_files.get(path.name)

        for record in records:
            match = URI_RE.search(record.strip())
            if not match:
                continue

            config = match.group(0).rstrip(".,;)]}")

            # Permanent archive: never remove previously imported configs.
            if config not in archive:
                archive[config] = {
                    "source_file": path.name,
                    "imported_at": now.isoformat()
                }
                imported += 1
                file_added += 1

            # Recent archive: only files published within the last 24 hours.
            if published_at is not None:
                existing = recent_archive.get(config)
                existing_published_at = (
                    parse_date(existing.get("published_at"))
                    if isinstance(existing, dict)
                    else None
                )

                if (
                    existing_published_at is None
                    or published_at > existing_published_at
                ):
                    recent_archive[config] = {
                        "source_file": path.name,
                        "published_at": published_at.isoformat()
                    }

        print(
            f"[INFO] {path.name}: {token_count} tokens, "
            f"{file_added} new links, {len(errors)} token errors"
        )

    ARCHIVE_PATH.write_text(
        json.dumps(archive, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    RECENT_PATH.write_text(
        json.dumps(recent_archive, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8"
    )

    print(f"[INFO] NPVT files decoded: {decoded_files}")
    print(f"[INFO] NPVT archive total (permanent): {len(archive)}")
    print(f"[INFO] NPVT newly imported: {imported}")
    print(f"[INFO] Recent NPVT files (last 24h): {len(recent_files)}")
    print(f"[INFO] Recent NPVT configs (last 24h): {len(recent_archive)}")


if __name__ == "__main__":
    main()
