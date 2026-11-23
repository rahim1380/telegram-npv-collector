#!/usr/bin/env python3
"""Decode legacy NPV Tunnel NPVT1 exports using public Kumo white-box tables."""
import argparse
import base64
import json
import re
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlencode

REV = "4db8fdb30f9a4cc6270d4281269c446a1616647b"
BASE = f"https://raw.githubusercontent.com/AbolDev/kumo-client/{REV}/assets/npvs/"
TABLE_FILES = ("tyboxes.bin", "mbl.bin", "tboxes_last_v2.bin", "xor.bin")
SHIFT = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)


def get_tables(folder: Path, download: bool):
    folder.mkdir(parents=True, exist_ok=True)
    for name in TABLE_FILES:
        p = folder / name
        if not p.exists():
            if not download:
                raise RuntimeError(f"Missing table {p}; use --download-tables")
            req = urllib.request.Request(BASE + name, headers={"User-Agent": "npvt-decoder/1.0"})
            with urllib.request.urlopen(req, timeout=30) as response:
                p.write_bytes(response.read())
    ty_b = (folder / "tyboxes.bin").read_bytes()
    mbl_b = (folder / "mbl.bin").read_bytes()
    last_b = (folder / "tboxes_last_v2.bin").read_bytes()
    xor = (folder / "xor.bin").read_bytes()
    if (len(ty_b), len(mbl_b), len(last_b), len(xor)) != (16384, 16384, 4096, 24576):
        raise RuntimeError("White-box table size mismatch; wrong or incomplete table set")
    ty = [[int.from_bytes(ty_b[i*1024+j*4:i*1024+j*4+4], "big") for j in range(256)] for i in range(16)]
    mbl = [[int.from_bytes(mbl_b[i*1024+j*4:i*1024+j*4+4], "big") for j in range(256)] for i in range(16)]
    return ty, mbl, last_b, xor


class WhiteBox:
    def __init__(self, tables):
        self.ty, self.mbl, self.last, self.xor = tables

    def x(self, t, a, b):
        return self.xor[(t << 8) + (a << 4) + b]

    def mix(self, grp, k, a, b, c, d):
        t = grp * 24 + k * 6
        hi, lo = 28 - 8*k, 24 - 8*k
        p1 = self.x(t, (a >> hi) & 15, (b >> hi) & 15)
        p2 = self.x(t+1, (c >> hi) & 15, (d >> hi) & 15)
        p3 = self.x(t+2, (a >> lo) & 15, (b >> lo) & 15)
        p4 = self.x(t+3, (c >> lo) & 15, (d >> lo) & 15)
        return (self.x(t+4, p1, p2) << 4) | self.x(t+5, p3, p4)

    def row(self, s, base, table, grp):
        a, b, c, d = (table[base+i][s[base+i]] for i in range(4))
        for k in range(4):
            s[base+k] = self.mix(grp, k, a, b, c, d)

    def block(self, block):
        s = [block[i] for i in SHIFT]
        for grp in range(4):
            self.row(s, grp*4, self.ty, grp)
            self.row(s, grp*4, self.mbl, grp)
        s = [s[i] for i in SHIFT]
        return bytes(self.last[i*256+s[i]] for i in range(16))

    def ctr(self, nonce, data):
        counter = bytearray(nonce[:16])
        out = bytearray(len(data))
        for offset in range(0, len(data), 16):
            ks = self.block(counter)
            n = min(16, len(data)-offset)
            for j in range(n):
                out[offset+j] = data[offset+j] ^ ks[j]
            for p in range(15, -1, -1):
                counter[p] = (counter[p] + 1) & 255
                if counter[p]:
                    break
        return bytes(out)


def parse_token(text):
    text = re.sub(r"\s+", "", text.replace("NPVT1", ""))
    if not text:
        return b""
    if len(text) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", text):
        return bytes.fromhex(text)
    padded = text + "=" * ((4-len(text) % 4) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except Exception:
        return base64.urlsafe_b64decode(padded)


def profile_to_link(item):
    profile = item.get("v2rayProfile")
    if not isinstance(profile, dict):
        return None

    raw_json = profile.get("v2rayJson")
    if raw_json:
        try:
            obj = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
            links = list(outbound_links(obj)) if isinstance(obj, dict) else []
            if links:
                return links[0]
        except (TypeError, ValueError):
            pass

    server = str(profile.get("server") or "").strip()
    port = str(profile.get("serverPort") or "").strip()
    if not server or not port:
        address = str(item.get("address") or "").strip()
        if ":" in address:
            server, port = address.rsplit(":", 1)
    if not server or not port:
        return None

    name = str(item.get("name") or profile.get("remarks") or "NPVT")
    config_type = str(profile.get("configType") or "")
    password = str(profile.get("password") or "")
    network = str(profile.get("network") or "tcp").lower()
    security = str(profile.get("security") or "none").lower()

    params = {"type": network, "security": security}
    if profile.get("sni"):
        params["sni"] = str(profile["sni"])
    if profile.get("fingerPrint"):
        params["fp"] = str(profile["fingerPrint"])
    if profile.get("alpn"):
        params["alpn"] = ",".join(profile["alpn"]) if isinstance(profile["alpn"], list) else str(profile["alpn"])
    if profile.get("insecure") is True:
        params["allowInsecure"] = "1"

    if security == "reality":
        if profile.get("publicKey"):
            params["pbk"] = str(profile["publicKey"])
        if profile.get("shortId"):
            params["sid"] = str(profile["shortId"])
        if profile.get("spiderX"):
            params["spx"] = str(profile["spiderX"])

    if network in ("ws", "websocket"):
        params["type"] = "ws"
        params["path"] = str(profile.get("path") or "/")
        if profile.get("host"):
            params["host"] = str(profile["host"])
    elif network == "grpc":
        if profile.get("serviceName"):
            params["serviceName"] = str(profile["serviceName"])
        if profile.get("mode"):
            params["mode"] = str(profile["mode"])
    elif network == "xhttp":
        if profile.get("mode"):
            params["mode"] = str(profile["mode"])

    encoded_name = quote(name, safe="")
    target = hostport(server, port)

    # NPVT configType values: 1=VMess, 3=Shadowsocks, 5=VLESS, 6=Trojan.
    if config_type == "3":
        method = str(profile.get("method") or "").strip()
        if not method or not password:
            return None
        auth = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return f"ss://{auth}@{target}#{encoded_name}"

    if config_type == "5":
        if not password:
            return None
        params["encryption"] = str(profile.get("encryption") or "none")
        if profile.get("flow"):
            params["flow"] = str(profile["flow"])
        return f"vless://{quote(password, safe='')}@{target}?{qencode(params)}#{encoded_name}"

    if config_type == "6":
        if not password:
            return None
        return f"trojan://{quote(password, safe='')}@{target}?{qencode(params)}#{encoded_name}"

    if config_type == "1":
        if not password:
            return None
        vmess = {
            "v": "2", "ps": name, "add": server, "port": port,
            "id": password, "aid": str(profile.get("alterId") or 0),
            "scy": str(profile.get("method") or "auto"),
            "net": network, "type": str(profile.get("headerType") or "none"),
            "host": str(profile.get("host") or ""),
            "path": str(profile.get("path") or ""),
            "tls": "tls" if security in ("tls", "reality") else "",
            "sni": str(profile.get("sni") or ""),
            "fp": str(profile.get("fingerPrint") or ""),
        }
        token = base64.b64encode(json.dumps(vmess, separators=(",", ":"), ensure_ascii=False).encode()).decode()
        return "vmess://" + token

    return None


def walk_json(value):
    if isinstance(value, dict):
        link = profile_to_link(value)
        if link:
            yield link

        raw = value.get("v2rayJson")
        if isinstance(raw, str):
            try:
                yield from walk_json(json.loads(raw))
            except Exception:
                pass
        elif isinstance(raw, dict):
            yield from walk_json(raw)
        if isinstance(value.get("outbounds"), list):
            yield from outbound_links(value)
        for k, v in value.items():
            if k not in ("v2rayJson", "outbounds", "v2rayProfile"):
                yield from walk_json(v)
    elif isinstance(value, list):
        for v in value:
            yield from walk_json(v)

def qencode(params):
    return urlencode(sorted(params.items()), doseq=True, quote_via=quote, safe="~")


def hostport(host, port):
    host = str(host or "").strip("[]")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def outbound_links(cfg):
    for ob in cfg.get("outbounds", []):
        if not isinstance(ob, dict):
            continue
        proto, settings = ob.get("protocol"), ob.get("settings") or {}
        stream = ob.get("streamSettings") or {}
        remarks = str(cfg.get("remarks") or ob.get("tag") or "")
        network = stream.get("network") or "tcp"
        security = stream.get("security") or "none"
        params = {"type": network, "security": security}
        if network == "ws":
            ws = stream.get("wsSettings") or {}
            if ws.get("path"):
                params["path"] = ws["path"]
            headers = ws.get("headers") or {}
            h = ws.get("host") or headers.get("Host") or headers.get("host")
            if h:
                params["host"] = ",".join(h) if isinstance(h, list) else str(h)
        if security == "tls":
            tls = stream.get("tlsSettings") or {}
            for src, dst in (("serverName", "sni"), ("fingerprint", "fp"), ("alpn", "alpn")):
                if tls.get(src):
                    params[dst] = ",".join(tls[src]) if isinstance(tls[src], list) else tls[src]
            if tls.get("allowInsecure"):
                params["allowInsecure"] = "1"
        if proto == "trojan":
            for server in settings.get("servers", []):
                pw = quote(str(server.get("password", "")), safe="-._~")
                yield f"trojan://{pw}@{hostport(server.get('address'), server.get('port'))}?{qencode(params)}#{quote(remarks)}"
        elif proto == "vless":
            for server in settings.get("vnext", []):
                for user in server.get("users", []):
                    p = dict(params, encryption=user.get("encryption") or "none")
                    if user.get("flow"):
                        p["flow"] = user["flow"]
                    yield f"vless://{user.get('id')}@{hostport(server.get('address'), server.get('port'))}?{qencode(p)}#{quote(remarks)}"
        elif proto == "shadowsocks":
            for server in settings.get("servers", []):
                auth = base64.b64encode(f"{server.get('method', '')}:{server.get('password', '')}".encode()).decode()
                yield f"ss://{auth}@{hostport(server.get('address'), server.get('port'))}#{quote(remarks)}"
        elif proto == "vmess":
            for server in settings.get("vnext", []):
                for user in server.get("users", []):
                    obj = {"v": "2", "ps": remarks, "add": server.get("address", ""), "port": str(server.get("port", 0)),
                           "id": user.get("id", ""), "aid": str(user.get("alterId", 0)), "scy": user.get("security", ""),
                           "net": network, "type": "none", "host": "", "path": "",
                           "tls": "tls" if security in ("tls", "reality") else ""}
                    yield "vmess://" + base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def decode_file(input_path: Path, tables_dir: Path, download_tables: bool = False):
    tables = get_tables(tables_dir, download_tables)
    wb = WhiteBox(tables)
    raw = input_path.read_text(encoding="utf-8-sig", errors="replace").strip()
    raw = re.sub(r"^NPVT1", "", raw).strip()
    results, errors = [], []
    for idx, token in enumerate(raw.split(","), 1):
        if not token.strip():
            continue
        try:
            blob = parse_token(token)
            if len(blob) < 16:
                raise ValueError(f"token only {len(blob)} bytes")
            plain = wb.ctr(blob[:16], blob[16:])
            decoded = plain.strip(b" \t\r\n")
            obj = json.loads(decoded.decode("utf-8"))
            before = len(results)
            results.extend(walk_json(obj))
            if len(results) == before:
                results.append("// JSON: " + json.dumps(obj, ensure_ascii=False))
        except Exception as exc:
            errors.append(f"// token {idx}: {type(exc).__name__}: {exc}")
    unique = list(dict.fromkeys(results))
    return unique, errors, len([t for t in raw.split(",") if t.strip()])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", type=Path)
    ap.add_argument("--tables-dir", type=Path, default=Path("npvt_tables"))
    ap.add_argument("--download-tables", action="store_true")
    ap.add_argument("--output", type=Path, default=Path("npvt_decoded.txt"))
    args = ap.parse_args()
    unique, errors, processed = decode_file(args.input, args.tables_dir, args.download_tables)
    output = "\n".join(unique + errors) + ("\n" if unique or errors else "")
    args.output.write_text(output, encoding="utf-8")
    print(f"Tokens processed: {processed}")
    print(f"Links/JSON records: {len(unique)}")
    print(f"Errors: {len(errors)}")
    print(f"Output: {args.output.resolve()}")
    for line in unique[:10]:
        print(line)


if __name__ == "__main__":
    main()
