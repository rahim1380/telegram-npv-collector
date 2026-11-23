#!/usr/bin/env python3
"""Download new .npvt documents from configured Telegram channels."""
import asyncio
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telethon import TelegramClient
from telethon.errors import FloodWaitError
from telethon.sessions import StringSession

CHANNELS = [
    "MARAMBASHI", "v2ray_Mammad", "levconnect", "iranping24",
    "Configvibes", "JOFAVPN", "VConfing", "appsooner",
    "SkyLiink_vpn", "haj_config", "V2RAYROZ", "PasargadConfig",
    "irannodes", "V2RAYNG_Outline_VPN", "yorpeanel",
    "Nexus_Panell", "JKVPN",
]

INPUT_DIR = Path("npvt_inputs")
DATA_DIR = Path("data")
STATE_PATH = DATA_DIR / "npvt_telegram_state.json"
HASH_PATH = DATA_DIR / "npvt_download_hashes.json"
FIRST_SCAN_LIMIT = 1000
RECENT_HOURS = 24


def utc_now():
    return datetime.now(timezone.utc)


def read_json(path, default):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else default
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temp, path)


def safe_filename(value):
    value = Path(value or "attachment.npvt").name
    value = re.sub(r"[^\w.\-() ]+", "_", value, flags=re.UNICODE).strip(" .")
    if not value:
        value = "attachment.npvt"
    if not value.lower().endswith(".npvt"):
        value += ".npvt"
    return value[:150]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def keep_recent_downloads(items):
    now = utc_now()
    cutoff = now - timedelta(hours=RECENT_HOURS)
    kept = []

    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            timestamp = datetime.fromisoformat(
                item["published_at"].replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            timestamp = timestamp.astimezone(timezone.utc)

            if cutoff <= timestamp <= now:
                kept.append(item)
        except (KeyError, TypeError, ValueError):
            continue

    return kept


def add_recent_event(recent, published_at, channel, message_id, filename, digest):
    event = {
        "published_at": published_at.isoformat(),
        "channel": channel,
        "message_id": message_id,
        "file": filename,
        "sha256": digest,
    }

    for index, old in enumerate(recent):
        if (
            old.get("channel") == channel
            and old.get("message_id") == message_id
        ):
            recent[index] = event
            return

    recent.append(event)


async def scan_channel(client, channel, state, hashes, recent):
    previous_id = int(state.get("channels", {}).get(channel, 0) or 0)
    entity = await client.get_entity(channel)
    newest_id = previous_id
    scanned = 0
    downloaded = 0

    now = utc_now()
    cutoff = now - timedelta(hours=RECENT_HOURS)

    # Re-scan all messages from the last 24 hours on every run.
    messages = client.iter_messages(
        entity,
        offset_date=cutoff,
        reverse=True,
    )

    async for message in messages:
        scanned += 1

        if message.id and message.id > newest_id:
            newest_id = message.id

        if not message.date:
            continue

        published_at = message.date
        if published_at.tzinfo is None:
            published_at = published_at.replace(tzinfo=timezone.utc)
        published_at = published_at.astimezone(timezone.utc)

        if not (cutoff <= published_at <= now):
            continue

        media_file = getattr(message, "file", None)
        original_name = getattr(media_file, "name", None) if media_file else None

        if not original_name or not original_name.lower().endswith(".npvt"):
            continue

        INPUT_DIR.mkdir(parents=True, exist_ok=True)
        safe_name = safe_filename(original_name)
        prefix = re.sub(r"[^\w-]+", "_", channel, flags=re.UNICODE)
        final_path = INPUT_DIR / f"{prefix}_{message.id}_{safe_name}"

        if final_path.exists():
            digest = sha256_file(final_path)
            hashes.setdefault(digest, {
                "file": final_path.name,
                "channel": channel,
                "message_id": message.id,
                "first_seen": utc_now().isoformat(),
            })
            add_recent_event(
                recent, published_at, channel, message.id,
                final_path.name, digest
            )
            continue

        fd, temp_name = tempfile.mkstemp(
            prefix="npvt_", suffix=".npvt", dir=str(INPUT_DIR)
        )
        os.close(fd)
        temp_path = Path(temp_name)

        try:
            result = await message.download_media(file=str(temp_path))
            if not result or not temp_path.exists() or temp_path.stat().st_size == 0:
                raise RuntimeError(
                    f"{channel}/{message.id}: download returned no file; "
                    "channel checkpoint will not advance"
                )

            digest = sha256_file(temp_path)

            if digest in hashes:
                existing_file = hashes[digest].get("file", final_path.name)
                add_recent_event(
                    recent, published_at, channel, message.id,
                    existing_file, digest
                )
                print(f"[SKIP] {channel}/{message.id}: duplicate SHA-256")
                continue

            os.replace(temp_path, final_path)

            hashes[digest] = {
                "file": final_path.name,
                "channel": channel,
                "message_id": message.id,
                "first_seen": utc_now().isoformat(),
            }

            add_recent_event(
                recent, published_at, channel, message.id,
                final_path.name, digest
            )

            downloaded += 1
            print(f"[DOWNLOADED] {channel}/{message.id}: {final_path.name}")

        finally:
            if temp_path.exists():
                temp_path.unlink()

    state.setdefault("channels", {})[channel] = newest_id

    print(
        f"[INFO] {channel}: scanned={scanned}, "
        f"downloaded={downloaded}, latest_id={newest_id}"
    )

    return downloaded


async def main():
    api_id = os.environ.get("TELEGRAM_API_ID", "").strip()
    api_hash = os.environ.get("TELEGRAM_API_HASH", "").strip()
    session_string = os.environ.get("TELEGRAM_SESSION", "").strip()

    if not api_id or not api_hash or not session_string:
        raise SystemExit(
            "Missing TELEGRAM_API_ID, TELEGRAM_API_HASH, or TELEGRAM_SESSION secret"
        )

    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    state = read_json(STATE_PATH, {"channels": {}})
    hashes = read_json(HASH_PATH, {})
    recent = state.get("recent_downloads", [])
    if not isinstance(recent, list):
        recent = []
    recent = keep_recent_downloads(recent)

    client = TelegramClient(StringSession(session_string), int(api_id), api_hash)
    await client.connect()

    try:
        if not await client.is_user_authorized():
            raise SystemExit(
                "Telegram session is not authorized; renew it locally and update the GitHub secret"
            )

        me = await client.get_me()
        print(f"[INFO] Telegram session authorized (user_id={me.id})")

        total = 0
        for channel in CHANNELS:
            try:
                total += await scan_channel(client, channel, state, hashes, recent)
            except FloodWaitError as exc:
                print(
                    f"[WARN] {channel}: Telegram flood wait {exc.seconds}s; "
                    "channel will retry next run"
                )
            except Exception as exc:
                print(f"[WARN] {channel}: {type(exc).__name__}: {exc}")

        state["recent_downloads"] = recent
        write_json(HASH_PATH, hashes)
        write_json(STATE_PATH, state)

        print(
            f"[SUMMARY] newly_downloaded={total}; "
            f"permanent_hashes={len(hashes)}; recent_24h={len(recent)}"
        )
    finally:
        await client.disconnect()


if __name__ == "__main__":
    asyncio.run(main())
