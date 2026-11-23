
#!/usr/bin/env python3
"""Parse VLESS, VMess, Trojan and Shadowsocks URIs."""

import base64
import json
from urllib.parse import (
    urlsplit,
    parse_qs,
    unquote,
)


SUPPORTED = {"vless", "vmess", "trojan", "ss"}


def decode_base64(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)

    try:
        return base64.urlsafe_b64decode(value).decode("utf-8")
    except Exception:
        return base64.b64decode(value).decode("utf-8")


def parse_config(link):
    link = link.strip()

    if "://" not in link:
        raise ValueError("Invalid URI")

    protocol = link.split("://", 1)[0].lower()

    if protocol not in SUPPORTED:
        raise ValueError(f"Unsupported protocol: {protocol}")

    if protocol == "vmess":
        raw = decode_base64(link.split("://", 1)[1])
        data = json.loads(raw)

        return {
            "protocol": "vmess",
            "server": data["add"],
            "port": int(data["port"]),
            "uuid": data["id"],
            "alter_id": int(data.get("aid", 0)),
            "security": data.get("scy", "auto"),
            "network": data.get("net", "tcp"),
            "tls": data.get("tls", ""),
            "sni": data.get("sni", ""),
            "fingerprint": data.get("fp", ""),
            "alpn": data.get("alpn", ""),
            "host": data.get("host", ""),
            "path": data.get("path", ""),
            "header_type": data.get("type", "none"),
            "name": data.get("ps", ""),
        }

    if protocol == "ss":
        body = link.split("://", 1)[1].split("#", 1)[0]
        body = body.split("?", 1)[0]

        if "@" not in body:
            body = decode_base64(body)

        userinfo, address = body.rsplit("@", 1)

        userinfo = unquote(userinfo)

        if ":" not in userinfo:
            userinfo = decode_base64(userinfo)

        method, password = userinfo.split(":", 1)

        address = address.strip()

        if address.startswith("["):
            server, rest = address[1:].split("]", 1)
            port = rest.lstrip(":")
        else:
            server, port = address.rsplit(":", 1)

        return {
            "protocol": "shadowsocks",
            "server": server,
            "port": int(port),
            "method": method,
            "password": password,
        }

    parsed = urlsplit(link)

    params = {
        key: values[-1]
        for key, values in parse_qs(
            parsed.query,
            keep_blank_values=True
        ).items()
    }

    server = parsed.hostname
    port = parsed.port

    if not server or not port:
        raise ValueError("Missing server or port")

    result = {
        "protocol": protocol,
        "server": server,
        "port": port,
        "network": params.get("type", "tcp"),
        "security": params.get("security", "none"),
        "sni": params.get("sni", ""),
        "fingerprint": params.get("fp", ""),
        "alpn": params.get("alpn", ""),
        "host": params.get("host", ""),
        "path": params.get("path", ""),
        "mode": params.get("mode", ""),
        "service_name": params.get("serviceName", ""),
        "authority": params.get("authority", ""),
        "header_type": params.get("headerType", "none"),
        "allow_insecure": params.get("allowInsecure", "0"),
        "name": unquote(parsed.fragment),
    }

    if protocol == "vless":
        result.update({
            "uuid": unquote(parsed.username or ""),
            "encryption": params.get("encryption", "none"),
            "flow": params.get("flow", ""),
            "public_key": params.get("pbk", ""),
            "short_id": params.get("sid", ""),
            "spider_x": params.get("spx", ""),
        })

    elif protocol == "trojan":
        result.update({
            "password": unquote(parsed.username or ""),
            "public_key": params.get("pbk", ""),
            "short_id": params.get("sid", ""),
            "spider_x": params.get("spx", ""),
        })

    return result

def build_xray_outbound(config):
    """Convert a parsed VLESS config into an Xray outbound."""

    if config.get("protocol") != "vless":
        raise ValueError("This builder supports VLESS only")

    network = config.get("network", "tcp")
    security = config.get("security", "none")

    stream = {
        "network": network,
        "security": security,
    }

    if security == "tls":
        tls_settings = {
            "serverName": config.get("sni") or config["server"],
        }

        if config.get("fingerprint"):
            tls_settings["fingerprint"] = config["fingerprint"]

        if config.get("alpn"):
            tls_settings["alpn"] = [
                item.strip()
                for item in config["alpn"].split(",")
                if item.strip()
            ]

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings = {
            "serverName": config.get("sni", ""),
            "fingerprint": config.get("fingerprint") or "chrome",
            "publicKey": config.get("public_key", ""),
            "shortId": config.get("short_id", ""),
        }

        if config.get("spider_x"):
            reality_settings["spiderX"] = config["spider_x"]

        if not reality_settings["serverName"] or not reality_settings["publicKey"]:
            raise ValueError("Reality requires SNI and public key")

        stream["realitySettings"] = reality_settings

    elif security != "none":
        raise ValueError(f"Unsupported VLESS security: {security}")

    if network == "ws":
        ws_settings = {"path": config.get("path") or "/"}

        if config.get("host"):
            ws_settings["headers"] = {"Host": config["host"]}

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": config.get("service_name", ""),
            "authority": config.get("authority", ""),
        }

    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": config.get("path") or "/",
            "host": config.get("host") or config.get("authority", ""),
        }

    elif network == "xhttp":
        xhttp_settings = {
            "path": config.get("path") or "/",
            "mode": config.get("mode") or "auto",
        }

        if config.get("host") or config.get("authority"):
            xhttp_settings["host"] = (
                config.get("host") or config.get("authority")
            )

        stream["xhttpSettings"] = xhttp_settings

    elif network not in ("tcp", "raw"):
        raise ValueError(f"Unsupported VLESS network: {network}")

    user = {
        "id": config["uuid"],
        "encryption": config.get("encryption", "none"),
    }

    if config.get("flow"):
        user["flow"] = config["flow"]

    return {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {
            "vnext": [{
                "address": config["server"],
                "port": config["port"],
                "users": [user],
            }]
        },
        "streamSettings": stream,
    }


def build_vmess_outbound(config):
    """Convert a parsed VMess config into an Xray outbound."""

    if config.get("protocol") != "vmess":
        raise ValueError("This builder supports VMess only")

    network = config.get("network", "tcp")
    security = config.get("tls", "")

    user = {
        "id": config["uuid"],
        "alterId": int(config.get("alter_id", 0)),
        "security": config.get("security") or "auto",
    }

    stream = {
        "network": network,
        "security": "none",
    }

    if security == "tls":
        stream["security"] = "tls"
        tls_settings = {
            "serverName": config.get("sni") or config["server"],
        }

        if config.get("fingerprint"):
            tls_settings["fingerprint"] = config["fingerprint"]

        if config.get("alpn"):
            tls_settings["alpn"] = [
                item.strip()
                for item in config["alpn"].split(",")
                if item.strip()
            ]

        stream["tlsSettings"] = tls_settings

    elif security not in ("", "none"):
        raise ValueError(f"Unsupported VMess TLS setting: {security}")

    if network in ("tcp", "raw"):
        stream["network"] = "tcp"

        if config.get("header_type") == "http":
            stream["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "path": [config.get("path") or "/"],
                        "headers": {
                            "Host": [config.get("host") or config["server"]]
                        },
                    },
                }
            }

    elif network == "ws":
        ws_settings = {
            "path": config.get("path") or "/",
        }

        if config.get("host"):
            ws_settings["headers"] = {"Host": config["host"]}

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": config.get("service_name", ""),
            "authority": config.get("authority", ""),
        }

    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": config.get("path") or "/",
            "host": config.get("host") or config.get("authority", ""),
        }

    elif network == "xhttp":
        xhttp_settings = {
            "path": config.get("path") or "/",
            "mode": config.get("mode") or "auto",
        }

        if config.get("host") or config.get("authority"):
            xhttp_settings["host"] = (
                config.get("host") or config.get("authority")
            )

        stream["xhttpSettings"] = xhttp_settings

    else:
        raise ValueError(f"Unsupported VMess network: {network}")

    return {
        "tag": "proxy",
        "protocol": "vmess",
        "settings": {
            "vnext": [{
                "address": config["server"],
                "port": config["port"],
                "users": [user],
            }]
        },
        "streamSettings": stream,
    }


def build_trojan_outbound(config):
    """Convert a parsed Trojan config into an Xray outbound."""

    if config.get("protocol") != "trojan":
        raise ValueError("This builder supports Trojan only")

    network = config.get("network", "tcp")
    security = config.get("security", "tls")

    stream = {
        "network": network,
        "security": security,
    }

    if security == "tls":
        tls_settings = {
            "serverName": config.get("sni") or config["server"],
        }

        if config.get("fingerprint"):
            tls_settings["fingerprint"] = config["fingerprint"]

        if config.get("alpn"):
            tls_settings["alpn"] = [
                item.strip()
                for item in config["alpn"].split(",")
                if item.strip()
            ]

        stream["tlsSettings"] = tls_settings

    elif security == "reality":
        reality_settings = {
            "serverName": config.get("sni", ""),
            "fingerprint": config.get("fingerprint") or "chrome",
            "publicKey": config.get("public_key", ""),
            "shortId": config.get("short_id", ""),
        }

        if config.get("spider_x"):
            reality_settings["spiderX"] = config["spider_x"]

        if not reality_settings["serverName"] or not reality_settings["publicKey"]:
            raise ValueError("Reality requires SNI and public key")

        stream["realitySettings"] = reality_settings

    elif security != "none":
        raise ValueError(f"Unsupported Trojan security: {security}")

    if network == "ws":
        ws_settings = {
            "path": config.get("path") or "/",
        }

        if config.get("host"):
            ws_settings["headers"] = {"Host": config["host"]}

        stream["wsSettings"] = ws_settings

    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": config.get("service_name", ""),
            "authority": config.get("authority", ""),
        }

    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": config.get("path") or "/",
            "host": config.get("host") or config.get("authority", ""),
        }

    elif network == "xhttp":
        xhttp_settings = {
            "path": config.get("path") or "/",
            "mode": config.get("mode") or "auto",
        }

        if config.get("host") or config.get("authority"):
            xhttp_settings["host"] = (
                config.get("host") or config.get("authority")
            )

        stream["xhttpSettings"] = xhttp_settings

    elif network not in ("tcp", "raw"):
        raise ValueError(f"Unsupported Trojan network: {network}")

    return {
        "tag": "proxy",
        "protocol": "trojan",
        "settings": {
            "servers": [{
                "address": config["server"],
                "port": config["port"],
                "password": config["password"],
            }]
        },
        "streamSettings": stream,
    }


def build_ss_outbound(config):
    """Convert a parsed Shadowsocks config into an Xray outbound."""

    if config.get("protocol") != "shadowsocks":
        raise ValueError("This builder supports Shadowsocks only")

    return {
        "tag": "proxy",
        "protocol": "shadowsocks",
        "settings": {
            "servers": [{
                "address": config["server"],
                "port": config["port"],
                "method": config["method"],
                "password": config["password"],
            }]
        },
    }
if __name__ == "__main__":
    print("NPVT config parser loaded successfully.")
    print("Supported protocols:", ", ".join(sorted(SUPPORTED)))
