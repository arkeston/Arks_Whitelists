#!/usr/bin/env python3
import base64
import urllib.request
import sys
import re
from urllib.parse import urlparse

# Сюда вставляй ТОЛЬКО исходные подписки (не merged_sub.txt!)
SUBSCRIPTION_LINKS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

def is_likely_subscription_url(url: str) -> bool:
    url_lower = url.lower()
    if "merged_sub.txt" in url_lower or "merged.txt" in url_lower:
        return False
    return True

def fetch_subscription(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="ignore")

def decode_if_base64(text: str) -> str:
    text = text.strip()
    if len(text) > 50 and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            if "\n" in decoded or "://" in decoded:
                return decoded
        except Exception:
            pass
    return text

def normalize_node(node: str) -> str | None:
    node = node.strip()
    if not node:
        return None

    if "://" not in node:
        # Это не URL — можно либо отбросить, либо попробовать обработать как base64 (если нужно)
        return None

    try:
        parsed = urlparse(node)
        if not parsed.scheme or not parsed.netloc:
            return None
    except Exception:
        return None

    # ВАЖНО: убрал жёсткий фильтр по схемам, чтобы не отбрасывать всё подряд
    # Если хочешь вернуть — раскомментируй блок ниже:
    # valid_schemes = {"vless", "vmess", "trojan", "ss"}
    # if parsed.scheme.lower() not in valid_schemes:
    #     return None

    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    if parsed.path:
        normalized += parsed.path
    if parsed.query:
        normalized += "?" + parsed.query
    if parsed.fragment:
        normalized += "#" + parsed.fragment

    return normalized

def parse_nodes(content: str):
    nodes = []
    for i, line in enumerate(content.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        nodes.append(line)
    return nodes

def main():
    all_nodes = []
    skipped_urls = 0
    fetched_urls = 0
    broken_nodes = 0
    duplicate_nodes = 0

    print(f"--- Начинаем обработку {len(SUBSCRIPTION_LINKS)} ссылок ---")

    for link in SUBSCRIPTION_LINKS:
        link = link.strip()
        if not link:
            continue

        if not is_likely_subscription_url(link):
            print(f"[SKIP] Ссылка выглядит как итоговый файл, пропускаем: {link}")
            skipped_urls += 1
            continue

        content = ""
        try:
            if link.startswith(("http://", "https://")):
                print(f"[FETCH] Загружаем: {link}")
                content = fetch_subscription(link)
                fetched_urls += 1
            else:
                content = decode_if_base64(link)
        except Exception as e:
            print(f"[ERROR] Не удалось загрузить {link}: {e}")
            continue

        nodes = parse_nodes(content)
        print(f"[INFO] Из ссылки получено строк (до нормализации): {len(nodes)}")
        all_nodes.extend(nodes)

    seen_normalized = set()
    unique_nodes = []

    for node in all_nodes:
        norm = normalize_node(node)
        if norm is None:
            broken_nodes += 1
            # Раскомментируй, если хочешь видеть первые 20 битых строк в логах:
            if broken_nodes <= 20:
               print(f"[DEBUG-BROKEN] Отброшена строка: {node}")
            continue

        if norm in seen_normalized:
            duplicate_nodes += 1
            continue

        seen_normalized.add(norm)
        unique_nodes.append(node)

    with open("merged_sub.txt", "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node + "\n")

    print("--- Статистика ---")
    print(f"Fetched from URLs: {fetched_urls}")
    print(f"Skipped URLs: {skipped_urls}")
    print(f"Total raw lines parsed: {len(all_nodes)}")
    print(f"Broken/invalid nodes: {broken_nodes}")
    print(f"Duplicates removed: {duplicate_nodes}")
    print(f"Unique valid nodes: {len(unique_nodes)}")

if __name__ == "__main__":
    main()
