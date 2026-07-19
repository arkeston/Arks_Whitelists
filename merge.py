#!/usr/bin/env python3
import base64
import urllib.request
import urllib.parse
import json
import re
from urllib.error import URLError

SUBSCRIPTION_LINKS = [
    # Добавьте ваши ссылки сюда
]

def decode_base64(text):
    try:
        # Исправляем символы для корректного декодирования
        text = text.replace('-', '+').replace('_', '/')
        text = text + '=' * ((4 - len(text) % 4) % 4)
        decoded = base64.b64decode(text).decode('utf-8')
        return decoded
    except:
        return None

def extract_links(content):
    # Извлекаем все строки с протоколами
    return re.findall(r'\S+://[^\s]+', content)

def decode_subscription(raw):
    links = extract_links(raw)
    if links:
        return {'links': links, 'decoded': raw}
    
    # Пытаемся декодировать base64
    decoded = decode_base64(raw)
    if decoded:
        links = extract_links(decoded)
        if links:
            return {'links': links, 'decoded': decoded}
        
        # Проверяем двойное кодирование
        double_decoded = decode_base64(decoded)
        if double_decoded:
            links = extract_links(double_decoded)
            if links:
                return {'links': links, 'decoded': double_decoded, 'doubleEncoded': True}
    
    return {'links': [], 'decoded': raw}

def parse_link(link):
    try:
        parsed = urllib.parse.urlparse(link)
        query_params = dict(qc.split('=') for qc in parsed.query.split('&'))
        
        return {
            'type': parsed.scheme,
            'server': parsed.hostname,
            'server_port': parsed.port or 443,
            'uuid': query_params.get('id'),
            'password': query_params.get('password'),
            'method': query_params.get('security', query_params.get('method')),
            'private_key': query_params.get('key')
        }
    except:
        return None

def get_full_key(profile):
    return json.dumps({
        'type': profile['type'],
        'server': profile['server'],
        'port': profile['server_port'],
        'uuid': profile['uuid'],
        'password': profile['password'],
        'method': profile['method'],
        'private_key': profile['private_key']
    })

def main():
    all_profiles = []
    seen_keys = set()
    duplicate_count = 0
    invalid_count = 0
    
    for link in SUBSCRIPTION_LINKS:
        try:
            # Загружаем контент
            req = urllib.request.Request(link, headers={"User-Agent": "Mozilla/5.0"})
            content = urllib.request.urlopen(req).read().decode('utf-8')
            
            # Декодируем подписку
            decoded_data = decode_subscription(content)
            links = decoded_data['links']
            
            for l in links:
                profile = parse_link(l)
                if not profile:
                    invalid_count += 1
                    continue
                
                full_key = get_full_key(profile)
                if full_key in seen_keys:
                    duplicate_count += 1
                    continue
                
                seen_keys.add(full_key)
                all_profiles.append(l)
                
        except (URLError, ValueError) as e:
            print(f"Ошибка при обработке {link}: {str(e)}")
    
    # Сохраняем результат
    with open("merged_sub.txt", "w", encoding="utf-8") as f:
        for profile in all_profiles:
            f.write(profile + "\n")
    
    print(f"Загружено профилей: {len(all_profiles)}")
