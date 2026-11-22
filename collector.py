#!/usr/bin/env python3
"""Collect raw VPN config URIs from the last 24h of selected public Telegram channels.
No ping tests and no connection tests are performed.
"""
import base64
import json
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

CHANNELS = [
    "MARAMBASHI",
    "v2ray_Mammad",
    "Gp_config",
    "levconnect",
    "iranping24",
    "Configvibes",
    "JOFAVPN",
]
ROOT = Path(__file__).resolve().parent
ARCHIVE = ROOT / "data" / "configs.json"
OUTPUT = ROOT / "subscription.txt"
CUTOFF = datetime.now(timezone.utc) - timedelta(hours=24)
PATTERN = re.compile(r'(?i)(?:vless|vmess|trojan|ss)://[^\s<>"\']+')

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; PublicTelegramConfigCollector/1.0)"
}

def clean_uri(value: str) -> str:
    value = value.strip().strip("()[]{}<>\"'`,;")
    # Telegram post text sometimes leaves punctuation attached to a URI.
    while value and value[-1] in ".,!?":
        value = value[:-1]
    return value

def parse_page(html: str):
    soup = BeautifulSoup(html, "html.parser")
    found = []
    oldest = None

    for post in soup.select(".tgme_widget_message_wrap"):
        time_el = post.select_one("time[datetime]")
        if not time_el:
            continue
        try:
            posted = datetime.fromisoformat(time_el.get("datetime").replace("Z", "+00:00"))
            if posted.tzinfo is None:
                posted = posted.replace(tzinfo=timezone.utc)
        except Exception:
            continue

        if oldest is None or posted < oldest:
            oldest = posted
        if posted < CUTOFF:
            continue

        text_el = post.select_one(".tgme_widget_message_text")
        if not text_el:
            continue
        text = text_el.get_text(" ", strip=True)
        for match in PATTERN.findall(text):
            uri = clean_uri(match)
            if uri:
                found.append(uri)

    more = soup.select_one("a.tme_messages_more[href]")
    next_url = urljoin("https://t.me", more["href"]) if more else None
    return found, oldest, next_url

def main():
    ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    if ARCHIVE.exists():
        try:
            archive = json.loads(ARCHIVE.read_text(encoding="utf-8"))
        except Exception:
            archive = []
    else:
        archive = []

    known = set(archive)
    session = requests.Session()
    session.headers.update(HEADERS)

    newly_seen = 0
    for channel in CHANNELS:
        url = f"https://t.me/s/{channel}"
        visited = set()
        # Follow Telegram's "older messages" pagination while pages overlap the last 24h.
        for _ in range(15):
            if not url or url in visited:
                break
            visited.add(url)
            try:
                response = session.get(url, timeout=25)
                response.raise_for_status()
                items, oldest, next_url = parse_page(response.text)
            except Exception as exc:
                print(f"[WARN] {channel}: {exc}")
                break

            for item in items:
                if item not in known:
                    known.add(item)
                    archive.append(item)
                    newly_seen += 1

            if oldest is not None and oldest < CUTOFF:
                break
            url = next_url
            if url:
                time.sleep(0.7)

        print(f"[OK] @{channel}")

    # Stable order: keep historical entries, with new ones appended.
    ARCHIVE.write_text(json.dumps(archive, ensure_ascii=False, indent=2), encoding="utf-8")
    payload = "\n".join(archive).encode("utf-8")
    OUTPUT.write_text(base64.b64encode(payload).decode("ascii"), encoding="ascii")
    print(f"New configs: {newly_seen}; total archived: {len(archive)}")
    print(f"Wrote {OUTPUT.name} (Base64 subscription format).")

if __name__ == "__main__":
    main()
