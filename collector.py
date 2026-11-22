import base64
import json
import re
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup


# فقط این ۶ کانال بررسی می‌شوند
CHANNELS = [
    "MARAMBASHI",
    "v2ray_Mammad",
    "levconnect",
    "iranping24",
    "Configvibes",
    "JOFAVPN",
    "VConfing",
    "appsooner",
]

ARCHIVE_PATH = Path("data/archive.json")
BLACKLIST_PATH = Path("data/blacklist.txt")
OUTPUT_PATH = Path("subscription.txt")

HOURS_LIMIT = 24
MAX_PAGES = 100

PATTERN = re.compile(
    r"(?:vless|vmess|trojan|ss)://[^\s<>\"']+",
    re.IGNORECASE
)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; TelegramConfigCollector/1.0)"
}


def utc_now():
    return datetime.now(timezone.utc)


def parse_date(value):
    try:
        result = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def load_json(path, default):
    if not path.exists():
        return default

    try:
        with open(path, "r", encoding="utf-8") as file:
            return json.load(file)
    except (json.JSONDecodeError, OSError):
        return default


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as file:
        json.dump(
            data,
            file,
            ensure_ascii=False,
            indent=2
        )


def load_blacklist():
    if not BLACKLIST_PATH.exists():
        return set()

    with open(BLACKLIST_PATH, "r", encoding="utf-8") as file:
        return {
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        }


def extract_configs(text):
    found = set()

    for match in PATTERN.findall(text):
        config = match.strip().rstrip(".,;)]}")

        if config:
            found.add(config)

    return found


def collect_channel(channel, cutoff):
    url = f"https://t.me/s/{channel}"

    collected = {}
    before = None
    visited = set()

    session = requests.Session()
    session.headers.update(HEADERS)

    for page in range(MAX_PAGES):

        page_url = url

        if before:
            page_url += f"?before={before}"

        try:
            response = session.get(
                page_url,
                timeout=25
            )

            response.raise_for_status()

            soup = BeautifulSoup(
                response.text,
                "html.parser"
            )

        except requests.RequestException as error:
            print(f"[WARN] {channel}: {error}")
            break

        messages = soup.select(
            "div.tgme_widget_message_wrap"
        )

        if not messages:
            break

        oldest_date = None
        message_ids = []

        for message in messages:

            post = message.select_one(
                "div.tgme_widget_message"
            )

            if not post:
                continue

            post_id = post.get("data-post", "")

            if "/" in post_id:
                try:
                    message_id = int(post_id.rsplit("/", 1)[1])
                    message_ids.append(message_id)
                except ValueError:
                    pass

            date_element = message.select_one(
                "time[datetime]"
            )

            if not date_element:
                continue

            posted = parse_date(
                date_element.get("datetime", "")
            )

            if not posted:
                continue

            if oldest_date is None or posted < oldest_date:
                oldest_date = posted

            if posted < cutoff:
                continue

            text_element = message.select_one(
                ".tgme_widget_message_text"
            )

            if not text_element:
                continue

            text_content = text_element.get_text(
                " ",
                strip=True
            )

            configs = extract_configs(text_content)

            for config in configs:
                if config not in collected:
                    collected[config] = {
                        "published_at": posted.isoformat(),
                        "channel": channel
                    }

        if oldest_date and oldest_date <= cutoff:
            break

        if not message_ids:
            break

        next_before = min(message_ids)

        if next_before in visited:
            break

        visited.add(next_before)
        before = next_before

        time.sleep(0.7)

    session.close()

    print(
        f"[INFO] {channel}: {len(collected)} configs found"
    )

    return collected


def main():

    ARCHIVE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    BLACKLIST_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if not BLACKLIST_PATH.exists():
        BLACKLIST_PATH.write_text(
            "# هر کانفیگی که نمی‌خواهید برگردد، در یک خط قرار دهید\n",
            encoding="utf-8"
        )

    archive = load_json(ARCHIVE_PATH, {})

    if not isinstance(archive, dict):
        archive = {}

    blacklist = load_blacklist()

    now = utc_now()
    cutoff = now - timedelta(hours=HOURS_LIMIT)

    discovered = {}

    for channel in CHANNELS:

        results = collect_channel(
            channel,
            cutoff
        )

        for config, info in results.items():

            if config not in discovered:
                discovered[config] = info

    # ثبت دائمی کانفیگ‌ها در آرشیو
    for config, info in discovered.items():

        if config not in archive:

            archive[config] = {
                "first_seen": info["published_at"],
                "last_seen": info["published_at"],
                "channels": [info["channel"]]
            }

        else:

            record = archive[config]

            if not isinstance(record, dict):
                record = {
                    "first_seen": info["published_at"],
                    "last_seen": info["published_at"],
                    "channels": []
                }

            old_date = parse_date(
                record.get("last_seen", "")
            )

            new_date = parse_date(
                info["published_at"]
            )

            if new_date and (
                old_date is None or new_date > old_date
            ):
                record["last_seen"] = new_date.isoformat()

            channels = record.get("channels", [])

            if not isinstance(channels, list):
                channels = []

            if info["channel"] not in channels:
                channels.append(info["channel"])

            record["channels"] = channels
            archive[config] = record

    # ذخیره آرشیو دائمی
    save_json(ARCHIVE_PATH, archive)

    # انتخاب کانفیگ‌های ۲۴ ساعت اخیر
    active_configs = []

    for config, record in archive.items():

        if config in blacklist:
            continue

        if not isinstance(record, dict):
            continue

        last_seen = parse_date(
            record.get("last_seen", "")
        )

        if not last_seen:
            continue

        if cutoff <= last_seen <= now:
            active_configs.append(config)

    # ساخت Subscription
    content = "\n".join(active_configs)

    encoded = base64.b64encode(
        content.encode("utf-8")
    ).decode("utf-8")

    OUTPUT_PATH.write_text(
        encoded,
        encoding="utf-8"
    )

    print("--------------------------------")
    print(f"Newly discovered: {len(discovered)}")
    print(f"Total archived: {len(archive)}")
    print(f"Blacklisted: {len(blacklist)}")
    print(f"Active configs: {len(active_configs)}")
    print("Subscription updated successfully")
    print("--------------------------------")


if __name__ == "__main__":
    main()
