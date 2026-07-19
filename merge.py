#!/usr/bin/env python3
import base64
import urllib.request
import sys
import re

# Сюда вставляй ТОЛЬКО исходные подписки (не merged_sub.txt!)
SUBSCRIPTION_LINKS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
]

def is_likely_subscription_url(url: str) -> bool:
    # Простая защита: если ссылка ведёт на merged_sub.txt или содержит очевидные признаки результата — пропускаем
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
    # Очень грубая эвристика: если строка длинная, состоит из base64 символов и не содержит переносов — пробуем декодировать
    if len(text) > 50 and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text).decode("utf-8", errors="ignore")
            # Если после декодирования видим много переносов или протоколы — считаем успешным
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
        # Пропускаем комментарии (часто в подписках бывает #)
        if line.startswith("#"):
            continue
        # Оставляем только строки, где есть протокол (vless://, vmess:// и т.п.)
        if "://" in line:
            nodes.append(line)
    return nodes

def main():
    all_nodes = []
    skipped_urls = 0
    fetched_urls = 0

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
                content = fetch_subscription(link)
                fetched_urls += 1
            else:
                # Если вдруг передаёшь base64 прямо в списке
                content = decode_if_base64(link)
        except Exception as e:
            print(f"[ERROR] Не удалось загрузить {link}: {e}")
            continue

        nodes = parse_nodes(content)
        all_nodes.extend(nodes)

    seen = set()
    unique_nodes = []
    for node in all_nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)

    # Сохраняем результат
    with open("merged_sub.txt", "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node + "\n")

    print(f"Done: fetched from {fetched_urls} URLs, skipped {skipped_urls} URLs")
    print(f"Total lines parsed: {len(all_nodes)}")
    print(f"Unique nodes: {len(unique_nodes)}")

if __name__ == "__main__":
    main()
