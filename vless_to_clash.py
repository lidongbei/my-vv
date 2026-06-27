#!/usr/bin/env python3
"""Convert multi-line vless:// share links into a Clash Meta YAML file.

Default usage:
    python3 vless_to_clash.py

By default the script reads nodes.txt from the current directory, applies
project-friendly defaults, and writes clash.yaml.

Other usage:
    python3 vless_to_clash.py -i nodes.txt -o clash.yaml

Or paste links through stdin:
    python3 vless_to_clash.py -o clash.yaml <<'EOF'
    vless://uuid@example.com:443?security=tls&type=ws&path=/chat#node-name
    EOF

The generated Clash config follows the structure of template_demo.yaml: DNS,
Chinese proxy groups, ACL4SSR rule providers, and rules are included; only the
proxies are generated from the vless:// links.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit


DEFAULT_INPUT = "nodes.txt"
DEFAULT_OUTPUT = "clash.yaml"
DEFAULT_TEST_URL = "http://www.gstatic.com/generate_204"
DEFAULT_SKIP_CERT_VERIFY = True
DEFAULT_FINGERPRINT = "chrome"


RULE_PROVIDERS: dict[str, dict[str, str]] = {
    "LocalAreaNetwork": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/LocalAreaNetwork.list",
        "path": "./rules/LocalAreaNetwork.yaml",
    },
    "BanAD": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/BanAD.list",
        "path": "./rules/BanAD.yaml",
    },
    "BanProgramAD": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/BanProgramAD.list",
        "path": "./rules/BanProgramAD.yaml",
    },
    "GoogleCN": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/GoogleCN.list",
        "path": "./rules/GoogleCN.yaml",
    },
    "SteamCN": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Ruleset/SteamCN.list",
        "path": "./rules/SteamCN.yaml",
    },
    "Microsoft": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Microsoft.list",
        "path": "./rules/Microsoft.yaml",
    },
    "Apple": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Apple.list",
        "path": "./rules/Apple.yaml",
    },
    "ProxyMedia": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ProxyMedia.list",
        "path": "./rules/ProxyMedia.yaml",
    },
    "Telegram": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/Telegram.list",
        "path": "./rules/Telegram.yaml",
    },
    "ProxyLite": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ProxyLite.list",
        "path": "./rules/ProxyLite.yaml",
    },
    "ChinaDomain": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ChinaDomain.list",
        "path": "./rules/ChinaDomain.yaml",
    },
    "ChinaCompanyIp": {
        "type": "http",
        "behavior": "classical",
        "url": "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/refs/heads/master/Clash/ChinaCompanyIp.list",
        "path": "./rules/ChinaCompanyIp.yaml",
    },
}


RULES = [
    "DOMAIN-SUFFIX,nodebuf.com,🚀 节点选择",
    "RULE-SET,LocalAreaNetwork,🎯 全球直连",
    "RULE-SET,BanAD,🛑 全球拦截",
    "RULE-SET,BanProgramAD,🍃 应用净化",
    "RULE-SET,GoogleCN,🎯 全球直连",
    "RULE-SET,SteamCN,🎯 全球直连",
    "RULE-SET,Microsoft,Ⓜ️ 微软服务",
    "RULE-SET,Apple,🍎 苹果服务",
    "RULE-SET,ProxyMedia,🌍 国外媒体",
    "RULE-SET,Telegram,📲 电报信息",
    "RULE-SET,ProxyLite,🚀 节点选择",
    "RULE-SET,ChinaDomain,🎯 全球直连",
    "RULE-SET,ChinaCompanyIp,🎯 全球直连",
    "GEOIP,CN,🎯 全球直连",
    "MATCH,🐟 漏网之鱼",
]


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)

    text = str(value)
    text = text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    return f'"{text}"'


def dump_yaml(value: Any, indent: int = 0) -> list[str]:
    prefix = " " * indent
    lines: list[str] = []

    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.extend(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}{key}: {yaml_scalar(item)}")
        return lines

    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                if not item:
                    lines.append(f"{prefix}- {{}}")
                    continue
                first = True
                for key, child in item.items():
                    key_prefix = "-" if first else " "
                    if isinstance(child, (dict, list)):
                        lines.append(f"{prefix}{key_prefix} {key}:")
                        lines.extend(dump_yaml(child, indent + 4))
                    else:
                        lines.append(f"{prefix}{key_prefix} {key}: {yaml_scalar(child)}")
                    first = False
            elif isinstance(item, list):
                lines.append(f"{prefix}-")
                lines.extend(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return lines

    return [f"{prefix}{yaml_scalar(value)}"]


def first_param(params: dict[str, list[str]], *names: str, default: str | None = None) -> str | None:
    lower_params = {key.lower(): value for key, value in params.items()}
    for name in names:
        values = lower_params.get(name.lower())
        if values:
            return values[0]
    return default


def split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    items = [item.strip() for item in value.split(",") if item.strip()]
    return items or None


def unique_name(name: str, used_names: set[str]) -> str:
    base = name.strip() or "vless"
    if base not in used_names:
        used_names.add(base)
        return base

    index = 1
    while f"{base}_{index}" in used_names:
        index += 1
    unique = f"{base}_{index}"
    used_names.add(unique)
    return unique


def parse_vless_link(
    link: str,
    index: int,
    used_names: set[str],
    skip_cert_verify: bool,
    default_fingerprint: str | None,
) -> dict[str, Any]:
    parsed = urlsplit(link)
    if parsed.scheme.lower() != "vless":
        raise ValueError("not a vless:// link")

    uuid = unquote(parsed.username or "")
    server = parsed.hostname
    if not uuid or not server:
        raise ValueError("missing uuid or server")

    params = parse_qs(parsed.query, keep_blank_values=True)
    security = (first_param(params, "security", default="none") or "none").lower()
    network = (first_param(params, "type", "network", default="tcp") or "tcp").lower()
    tls = security in {"tls", "reality"}
    port = parsed.port or (443 if tls else 80)
    name = unique_name(unquote(parsed.fragment) or f"vless-{index}", used_names)

    proxy: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid,
        "network": network,
        "tls": tls,
        "udp": True,
    }

    flow = first_param(params, "flow")
    if flow:
        proxy["flow"] = flow

    packet_encoding = first_param(params, "packetEncoding", "packet-encoding")
    if packet_encoding:
        proxy["packet-encoding"] = packet_encoding

    alpn = split_csv(first_param(params, "alpn"))
    if alpn:
        proxy["alpn"] = alpn

    if tls:
        sni = first_param(params, "sni", "servername", "peer") or server
        proxy["servername"] = sni
        proxy["skip-cert-verify"] = skip_cert_verify
        fingerprint = first_param(params, "fp", "fingerprint") or default_fingerprint
        if fingerprint:
            proxy["client-fingerprint"] = fingerprint

    if security == "reality":
        public_key = first_param(params, "pbk", "public-key", "publicKey")
        short_id = first_param(params, "sid", "short-id", "shortId")
        reality_opts: dict[str, Any] = {}
        if public_key:
            reality_opts["public-key"] = public_key
        if short_id:
            reality_opts["short-id"] = short_id
        if reality_opts:
            proxy["reality-opts"] = reality_opts

    if network == "ws":
        path = first_param(params, "path", default="/") or "/"
        host = first_param(params, "host")
        ws_opts: dict[str, Any] = {"path": path}
        if host:
            ws_opts["headers"] = {"Host": host}
        proxy["ws-opts"] = ws_opts
    elif network == "grpc":
        service_name = first_param(params, "serviceName", "service-name", "grpc-service-name")
        if service_name:
            proxy["grpc-opts"] = {"grpc-service-name": service_name}
    elif network in {"http", "h2"}:
        path = first_param(params, "path")
        host = first_param(params, "host")
        http_opts: dict[str, Any] = {}
        if path:
            http_opts["path"] = [path]
        if host:
            http_opts["headers"] = {"Host": [host]}
        if http_opts:
            proxy["http-opts"] = http_opts

    return proxy


def read_links(input_path: str | None, positional_links: list[str]) -> list[str]:
    raw_text = ""
    default_input_path = Path(DEFAULT_INPUT)

    if input_path:
        raw_text = Path(input_path).read_text(encoding="utf-8")
    elif positional_links:
        raw_text = "\n".join(positional_links)
    elif default_input_path.exists():
        raw_text = default_input_path.read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
    else:
        raise SystemExit(
            f"No input found. Put vless:// links in {DEFAULT_INPUT}, "
            "or pass -i nodes.txt, stdin, or positional arguments"
        )

    links: list[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for token in stripped.split():
            if token.startswith("vless://"):
                links.append(token)
            else:
                print(f"Skip unsupported line/token: {token}", file=sys.stderr)
    return links


def build_proxy_groups(proxy_names: list[str], test_url: str) -> list[dict[str, Any]]:
    node_select = ["♻️ 自动选择", "DIRECT"] + proxy_names
    node_chain = ["🚀 节点选择", "♻️ 自动选择", "DIRECT"] + proxy_names

    return [
        {
            "name": "🚀 节点选择",
            "type": "select",
            "proxies": node_select,
        },
        {
            "name": "♻️ 自动选择",
            "type": "url-test",
            "proxies": proxy_names,
            "url": test_url,
            "interval": 300,
            "tolerance": 50,
        },
        {
            "name": "🎯 全球直连",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"],
        },
        {
            "name": "🛑 全球拦截",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "🍃 应用净化",
            "type": "select",
            "proxies": ["REJECT", "DIRECT"],
        },
        {
            "name": "Ⓜ️ 微软服务",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"] + proxy_names,
        },
        {
            "name": "🍎 苹果服务",
            "type": "select",
            "proxies": ["DIRECT", "🚀 节点选择", "♻️ 自动选择"] + proxy_names,
        },
        {
            "name": "🌍 国外媒体",
            "type": "select",
            "proxies": node_chain,
        },
        {
            "name": "📲 电报信息",
            "type": "select",
            "proxies": node_chain,
        },
        {
            "name": "🐟 漏网之鱼",
            "type": "select",
            "proxies": node_chain,
        },
    ]


def build_clash_config(proxies: list[dict[str, Any]], test_url: str) -> dict[str, Any]:
    proxy_names = [proxy["name"] for proxy in proxies]
    return {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": True,
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": True,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "default-nameserver": ["223.5.5.5", "119.29.29.29"],
            "nameserver": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
        },
        "proxies": proxies,
        "proxy-groups": build_proxy_groups(proxy_names, test_url),
        "rule-providers": RULE_PROVIDERS,
        "rules": RULES,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Convert multi-line vless:// links to clash.yaml")
    parser.add_argument("links", nargs="*", help="vless:// links; alternatively use -i, nodes.txt, or stdin")
    parser.add_argument(
        "-i",
        "--input",
        help=f"text file containing one vless:// link per line; default: {DEFAULT_INPUT} if it exists",
    )
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help=f"output Clash YAML path; default: {DEFAULT_OUTPUT}")
    parser.add_argument("--test-url", default=DEFAULT_TEST_URL, help="URL used by url-test proxy group")
    parser.add_argument(
        "--skip-cert-verify",
        dest="skip_cert_verify",
        action="store_true",
        default=DEFAULT_SKIP_CERT_VERIFY,
        help="write skip-cert-verify: true for TLS/Reality nodes; default: true",
    )
    parser.add_argument(
        "--no-skip-cert-verify",
        dest="skip_cert_verify",
        action="store_false",
        help="write skip-cert-verify: false for TLS/Reality nodes",
    )
    parser.add_argument(
        "--fingerprint",
        default=DEFAULT_FINGERPRINT,
        help="default TLS client fingerprint when the link has no fp parameter; use '' to disable",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    links = read_links(args.input, args.links)
    if not links:
        raise SystemExit("No vless:// links found")

    used_names: set[str] = set()
    proxies: list[dict[str, Any]] = []
    errors: list[str] = []
    default_fingerprint = args.fingerprint or None

    for index, link in enumerate(links, start=1):
        try:
            proxies.append(
                parse_vless_link(
                    link=link,
                    index=index,
                    used_names=used_names,
                    skip_cert_verify=args.skip_cert_verify,
                    default_fingerprint=default_fingerprint,
                )
            )
        except ValueError as exc:
            errors.append(f"line/link {index}: {exc}")

    if errors:
        for error in errors:
            print(error, file=sys.stderr)
    if not proxies:
        raise SystemExit("No valid vless:// links parsed")

    clash_config = build_clash_config(proxies, args.test_url)
    output = "# Generated by vless_to_clash.py from vless:// links\n" + "\n".join(dump_yaml(clash_config)) + "\n"
    output_path = Path(args.output)
    output_path.write_text(output, encoding="utf-8")
    print(f"Wrote {output_path} with {len(proxies)} node(s)")


if __name__ == "__main__":
    main()
