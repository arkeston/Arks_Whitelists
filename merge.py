#!/usr/bin/env python3
import base64
import urllib.request
import sys

# ВСТАВЬ СЮДА СВОИ ССЫЛКИ НА ПОДПИСКИ
SUBSCRIPTION_LINKS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

def fetch_subscription(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore")

def decode_if_base64(text: str) -> str:
    try:
        if len(text) % 4 == 0 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in text):
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            if "\n" in decoded or "://" in decoded:
                return decoded
    except Exception:
        pass
    return text

def parse_nodes(content: str):
    nodes = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if "://" in line:
            nodes.append(line)
    return nodes

def main():
    all_nodes = []

    for link in SUBSCRIPTION_LINKS:
        link = link.strip()
        if not link:
            continue

        content = ""
        if link.startswith(("http://", "https://")):
            content = fetch_subscription(link)
        else:
            content = decode_if_base64(link)

        nodes = parse_nodes(content)
        all_nodes.extend(nodes)

    seen = set()
    unique_nodes = []
    for node in all_nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)

    # Вывод в merged_sub.txt
    with open("merged_sub.txt", "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node + "\n")

    print(f"Merged {len(all_nodes)} total nodes -> {len(unique_nodes)} unique nodes.")

if __name__ == "__main__":
    main()
