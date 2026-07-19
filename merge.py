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
    """
    Нормализация строки для дедупликации:
      - убираем лишние пробелы по краям
      - приводим к одному регистру (для протокола, хоста, порта)
      - оставляем параметры как есть (или можно дополнительно нормализовать, если нужно)
    Возвращает нормализованную строку или None, если профиль битый.
    """
    node = node.strip()
    if not node:
        return None

    # Базовая проверка: должен быть протокол и хост
    if "://" not in node:
        return None

    try:
        parsed = urlparse(node)
        if not parsed.scheme or not parsed.netloc:
            return None
    except Exception:
        return None

    # Простая эвристика: если схема не из ожидаемых — можно отбросить
    valid_schemes = {"vless", "vmess", "trojan", "ss"}
    if parsed.scheme.lower() not in valid_schemes:
        # Если у тебя нужны и другие схемы — удали эту проверку
        return None

    # Нормализуем: схема и netloc (host:port) в нижнем регистре
    # Параметры (query) оставляем как есть — они могут быть чувствительны
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
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if "://" in line:
            nodes.append(line)
    return nodes

def main():
    all_nodes = []
    skipped_urls = 0
    fetched_urls = 0
    broken_nodes = 0
    duplicate_nodes = 0

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
                content = decode_if_base64(link)
        except Exception as e:
            print(f"[ERROR] Не удалось загрузить {link}: {e}")
            continue

        nodes = parse_nodes(content)
        all_nodes.extend(nodes)

    seen_normalized = set()
    unique_nodes = []  # храним оригинальные строки (не нормализованные) для вывода

    for node in all_nodes:
        norm = normalize_node(node)
        if norm is None:
            broken_nodes += 1
            # Можно раскомментировать, чтобы видеть битые строки в логах
            print(f"[BROKEN] Отброшена строка: {node}")
            continue

        if norm in seen_normalized:
            duplicate_nodes += 1
            continue

        seen_normalized.add(norm)
        unique_nodes.append(node)  # сохраняем оригинал

    with open("merged_sub.txt", "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node + "\n")

    print(f"Done: fetched from {fetched_urls} URLs, skipped {skipped_urls} URLs")
    print(f"Total raw lines parsed: {len(all_nodes)}")
    print(f"Broken/invalid nodes: {broken_nodes}")
    print(f"Duplicates removed: {duplicate_nodes}")
    print(f"Unique valid nodes: {len(unique_nodes)}")

if __name__ == "__main__":
    main()
