from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import socket
import subprocess
import tempfile
import time

import requests

from config_tester import (
    parse_config,
    build_xray_outbound,
    build_vmess_outbound,
    build_trojan_outbound,
    build_ss_outbound,
)

XRAY = os.environ.get("XRAY_BIN", "xray")

SOURCE = Path("subscription.txt")
OUTPUT = Path("data/npvt_working_configs.txt")

BUILDERS = {
    "vless": build_xray_outbound,
    "vmess": build_vmess_outbound,
    "trojan": build_trojan_outbound,
    "shadowsocks": build_ss_outbound,
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_one(link):
    process = None

    try:
        config = parse_config(link)
        outbound = BUILDERS[config["protocol"]](config)
        port = free_port()

        xray_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "listen": "127.0.0.1",
                "port": port,
                "protocol": "socks",
                "settings": {"udp": False},
            }],
            "outbounds": [
                outbound,
                {"protocol": "freedom", "tag": "direct"},
            ],
        }

        with tempfile.TemporaryDirectory() as temp:
            config_path = Path(temp) / "xray.json"
            config_path.write_text(
                json.dumps(xray_config),
                encoding="utf-8",
            )

            process = subprocess.Popen(
                [XRAY, "run", "-c", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            ready = False
            for _ in range(40):
                if process.poll() is not None:
                    break
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=0.5
                    ):
                        ready = True
                        break
                except OSError:
                    time.sleep(0.25)

            if not ready:
                return False, "XRAY_START_FAILED"

            proxy = f"socks5h://127.0.0.1:{port}"
            response = requests.get(
                "https://www.gstatic.com/generate_204",
                proxies={"http": proxy, "https": proxy},
                timeout=15,
                allow_redirects=True,
            )

            return 200 <= response.status_code < 400, str(response.status_code)

    except Exception as e:
        return False, type(e).__name__

    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()


def main():
    raw = SOURCE.read_text(encoding="utf-8-sig").strip()
    decoded = __import__("base64").b64decode(
        raw + "=" * (-len(raw) % 4)
    ).decode("utf-8", errors="replace")
    links = [line.strip() for line in decoded.splitlines() if "://" in line]
    working = []

    print("TOTAL:", len(links))

    def run_item(item):
        index, link = item
        try:
            config = parse_config(link)
            protocol = config["protocol"]
        except Exception:
            protocol = "unknown"

        print(f"START {index}/{len(links)} {protocol}", flush=True)
        ok, result = test_one(link)
        return index, link, protocol, ok, result

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [
            executor.submit(run_item, item)
            for item in enumerate(links, 1)
        ]

        for future in as_completed(futures):
            index, link, protocol, ok, result = future.result()

            if ok:
                working.append(link)
                print(f"{index}/{len(links)} {protocol}: OK ({result})")
            else:
                print(f"{index}/{len(links)} {protocol}: FAIL ({result})")

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        "\n".join(working) + ("\n" if working else ""),
        encoding="utf-8",
    )

    if working:
        import base64
        filtered = "\n".join(working)
        encoded = base64.b64encode(filtered.encode("utf-8")).decode("ascii")
        SOURCE.write_text(encoded, encoding="utf-8")
        print("SUBSCRIPTION UPDATED:", len(working))
    else:
        print("ERROR: No working configs. Stopping workflow to preserve GitHub subscription.")
        raise SystemExit(1)

    print("FINISHED")
    print("SUCCESS:", len(working))
    print("SAVED:", OUTPUT)


if __name__ == "__main__":
    main()



