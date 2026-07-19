#!/usr/bin/env python3
import re
import base64
import json
import zlib
import gzip
import struct
import urllib.request, urllib.error # Replaced httpx with urllib.request and urllib.error
from typing import List, Dict, Any, Optional

# --- Placeholder/Helper Functions (to be implemented by the user) ---

def parse_wireguard_conf(conf_str: str, name: str) -> Optional[Dict[str, Any]]:
    """
    Placeholder for parsing WireGuard .conf files.
    Requires a dedicated library or custom parser.
    Returns a dictionary representing the outbound profile.
    """
    # Example: Simple check for Interface section
    if '[Interface]' in conf_str:
        print(f"[Placeholder] Parsing WireGuard config for {name}")
        # In a real scenario, you would parse the .conf file to extract
        # relevant WireGuard parameters like PrivateKey, Address, DNS, Endpoint, etc.
        # and structure it into an outbound object.
        # For now, return a dummy object if it looks like a WireGuard config.
        return {
            'type': 'wireguard',
            'tag': name,
            'server': 'example.com',
            'server_port': 51820,
            'private_key': 'YOUR_PRIVATE_KEY',
            'amnezia': 'AmneziaWG' in conf_str # Dummy check
        }
    return None

def extract_outbounds_from_config(json_str: str) -> List[Dict[str, Any]]:
    """
    Placeholder for extracting outbounds from a JSON configuration (e.g., sing-box).
    ""
    try:
        config = json.loads(json_str)
        outbounds = []
        # Assuming a structure like sing-box where 'outbounds' is a list of dicts
        if 'outbounds' in config and isinstance(config['outbounds'], list):
            for ob in config['outbounds']:
                # A simple check to ensure it's a valid-looking outbound
                if 'type' in ob and 'tag' in ob:
                    outbounds.append(ob)
            print(f"[Placeholder] Extracted {len(outbounds)} outbounds from JSON config.")
            return outbounds
        # If it's a single outbound object directly
        elif 'type' in config and 'tag' in config:
            print("[Placeholder] Extracted 1 outbound from direct JSON object.")
            return [config]
    except json.JSONDecodeError:
        print("[Placeholder] Invalid JSON for outbound extraction.")
    return []

def parse_link(link: str) -> Optional[Dict[str, Any]]:
    """
    Placeholder for parsing individual VPN links (vmess, vless, trojan, ss, etc.).
    This function is critical and needs a robust implementation for each protocol.
    """
    # In a real application, you'd have extensive logic here to parse
    # different VPN protocols (vmess://, vless://, ss://, trojan://, etc.)
    # and convert them into a standardized 'outbound' dictionary format.

    # For demonstration, a very basic example for vmess/vless/trojan
    if link.startswith('vmess://'):
        try:
            # vmess links are typically base64 encoded JSON
            b64_data = link[len('vmess://'):]
            # Handle URL-safe base64 if necessary (replace - with +, _ with /)
            b64_data = b64_data.replace('-', '+').replace('_', '/')
            # Add padding if missing
            padding = len(b64_data) % 4
            if padding != 0: b64_data += '=' * (4 - padding)

            decoded_json = base64.b64decode(b64_data).decode('utf-8')
            data = json.loads(decoded_json)
            return {
                'type': 'vmess',
                'tag': data.get('ps', f'vmess-{data.get("add") or "unknown"}'),
                'server': data.get('add'),
                'server_port': int(data.get('port')),
                'uuid': data.get('id'),
                'alterId': int(data.get('aid', 0)),
                'security': data.get('scy', 'auto'),
                'network': data.get('net', 'tcp'),
                'tls': {'enabled': data.get('tls', '') == 'tls'},
                'original_link': link # Store the original link
                # ... other vmess specific fields
            }
        except Exception as e:
            print(f"Error parsing vmess link: {e}")
            return None
    elif link.startswith('vless://') or link.startswith('trojan://') or link.startswith('ss://'):
        # These are usually in format: protocol://uuid@server:port?params#tag
        # A full parser would need to handle all parameters.
        match = re.match(r'(vless|trojan|ss)://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', link)
        if match:
            proto, user_id, server, port_str, params_str, tag = match.groups()
            port = int(port_str)
            outbound = {
                'type': proto,
                'tag': tag or f'{proto}-{server}',
                'server': server,
                'server_port': port,
                'original_link': link # Store the original link
            }
            if proto == 'vless':
                outbound['uuid'] = user_id
                outbound['tls'] = {'enabled': True}
                # Parse params for flow, type, security, fp, sni etc.
                if params_str:
                    params = dict(p.split('=') for p in params_str.split('&') if '=' in p)
                    outbound['flow'] = params.get('flow')
                    if 'security' in params and params['security'] == 'tls':
                        outbound['tls']['server_name'] = params.get('sni') or server
                        outbound['tls']['utls'] = {'enabled': True, 'fingerprint': params.get('fp', 'chrome')}
                    elif 'security' in params and params['security'] == 'reality':
                         outbound['tls']['reality'] = {'enabled': True, 'public_key': params.get('pbk'), 'short_id': params.get('sid')}
                    if 'type' in params and params['type'] in ['ws', 'grpc']:
                         outbound['transport'] = {'type': params['type'], 'path': params.get('path', ''), 'service_name': params.get('serviceName', '')}

            elif proto == 'trojan':
                outbound['password'] = user_id
                outbound['tls'] = {'enabled': True}
                # Parse params for type, security, fp, sni etc.
                if params_str:
                    params = dict(p.split('=') for p in params_str.split('&') if '=' in p)
                    if 'security' in params and params['security'] == 'tls':
                        outbound['tls']['server_name'] = params.get('sni') or server
                        outbound['tls']['utls'] = {'enabled': True, 'fingerprint': params.get('fp', 'chrome')}
                    if 'type' in params and params['type'] in ['ws', 'grpc']:
                        outbound['transport'] = {'type': params['type'], 'path': params.get('path', ''), 'service_name': params.get('serviceName', '')}

            elif proto == 'ss':
                # ss://method:password@server:port#tag
                method, password = user_id.split(':', 1)
                outbound['method'] = method
                outbound['password'] = password

            return outbound
        else:
            print(f"[Placeholder] Unrecognized format for {proto} link.")
            return None

    # Default / Unknown protocol
    return {
        'type': 'unknown',
        'tag': f'unknown-{link[:20]}',
        'link': link,
        'original_link': link # Store the original link for unknown types too
    }


# --- Core Logic Translation ---

def extract_links(text: str) -> List[str]:
    """
    Extracts links from text, similar to JS `extractLinks`.
    """
    return [line.strip() for line in text.splitlines() if '://' in line.strip()]

def decode_subscription(raw: str) -> Dict[str, Any]:
    """
    Decodes a subscription string, handling plain text, single base64, and double base64.
    Similar to JS `decodeSubscription`.
    """
    links = extract_links(raw)
    if links: # If links are found as plain text
        return {'links': links, 'decoded': raw, 'doubleEncoded': False}

    try:
        # Attempt first-level base64 decode
        d1 = base64.b64decode(raw.strip().replace(' ', '')).decode('utf-8', errors='ignore')
        links = extract_links(d1)
        if links:
            return {'links': links, 'decoded': d1, 'doubleEncoded': False}

        # Attempt second-level base64 decode (double encoding)
        try:
            d2 = base64.b64decode(d1.strip().replace(' ', '')).decode('utf-8', errors='ignore')
            links = extract_links(d2)
            if links:
                return {'links': links, 'decoded': d2, 'doubleEncoded': True}
        except Exception:
            pass # d2 decoding failed, return d1 result if links found

        # If d1 decoding worked but found no links, return d1 content anyway
        return {'links': extract_links(d1), 'decoded': d1, 'doubleEncoded': False}
    except Exception:
        pass # d1 decoding failed, return raw

    # If no base64 decoding worked, return raw
    return {'links': extract_links(raw), 'decoded': raw, 'doubleEncoded': False}

def parse_sn_link_async(url_str: str) -> Optional[Dict[str, Any]]:
    """
    Parses sn:// protocol links, including base64 decoding, decompression, and string extraction.
    Translated from JS `parseSNLinkAsync`.
    ""
    try:
        without_proto = url_str[5:] if url_str.startswith('sn://') else url_str

        proto_match = re.match(r'^([a-z0-9]+)\?(.+)$', without_proto)
        proto = proto_match.group(1) if proto_match else 'vmess'
        b64_part_raw = proto_match.group(2).split('#')[0] if proto_match else (without_proto.split('?', 1)[1] if '?' in without_proto else without_proto)

        # Base64 decode (handle URL-safe variants and padding)
        b64_part = b64_part_raw.replace('-', '+').replace('_', '/')
        padding_needed = len(b64_part) % 4
        if padding_needed != 0:
            b64_part += '=' * (4 - padding_needed)

        decoded_bytes = base64.b64decode(b64_part)

        raw_data = None

        # 1. Pure JSON
        try:
            text = decoded_bytes.decode('utf-8')
            if text.strip().startswith('{'):
                # If it's pure JSON, add the original_link to it before returning
                parsed_json = json.loads(text)
                parsed_json['original_link'] = url_str
                return parsed_json
        except Exception:
            pass

        # 2. Decompression -> JSON
        for fmt in ['deflate-raw', 'deflate', 'gzip']:
            try:
                if fmt == 'deflate-raw':
                    # zlib.decompress with negative wbits for raw deflate
                    decompressed_bytes = zlib.decompress(decoded_bytes, wbits=-zlib.MAX_WBITS)
                elif fmt == 'deflate':
                    decompressed_bytes = zlib.decompress(decoded_bytes)
                elif fmt == 'gzip':
                    decompressed_bytes = gzip.decompress(decoded_bytes)

                text = decompressed_bytes.decode('utf-8')
                if text.strip().startswith('{'):
                    # If it's JSON after decompression, add original_link
                    parsed_json = json.loads(text)
                    parsed_json['original_link'] = url_str
                    return parsed_json
            except Exception:
                pass

        # 3. NekoBox binary format (skip zlib header if present) and extract ASCII strings
        # Check for zlib header (0x78 xx)
        if decoded_bytes and decoded_bytes[0] == 0x78:
            for skip in [2, 0]: # Try skipping 2 bytes (common zlib header) then no skip
                try:
                    slice_bytes = decoded_bytes[skip:]
                    decompressed_bytes = zlib.decompress(slice_bytes, wbits=-zlib.MAX_WBITS) # Assume deflate-raw after header
                    raw_data = decompressed_bytes
                    break
                except Exception:
                    pass
        if not raw_data: # If no decompression or header skip worked, use original decoded bytes
            raw_data = decoded_bytes

        # Extract all ASCII strings (4+ chars)
        strings = []
        cur = []
        for c_byte in raw_data:
            if 0x20 <= c_byte < 0x7f: # ASCII printable characters
                cur.append(chr(c_byte))
            else:
                if len(cur) >= 4:
                    strings.append(''.join(cur))
                cur = []
        if len(cur) >= 4:
            strings.append(''.join(cur))

        # Extract UTF-8 tag (can contain emojis)
        tag_str = ''
        try:
            text_decoded_for_tag = raw_data.decode('utf-8', errors='ignore')
            tag_match = re.search(r'@[^\x00-\x1f]{3,80}', text_decoded_for_tag)
            if tag_match:
                tag_str = tag_match.group(0)
                # Replace control characters within the matched tag_str
                tag_str = re.sub(r'[\x00-\x1f]', '', tag_str).strip()
        except Exception:
            pass

        # Try to assemble outbound from extracted strings
        server = next((s for s in strings if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', s) or re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', s)), None)
        uuid = next((s for s in strings if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', s, re.IGNORECASE)), None)
        public_key = next((s for s in strings if re.match(r'^[A-Za-z0-9_\-]{40,50}$', s) and s != uuid), None)
        short_id = next((s for s in strings if re.match(r'^[0-9a-f]{8,16}$', s)), None)
        sni = next((s for s in strings if re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', s) and s != server), None)
        transport = next((s for s in strings if s in ['grpc', 'ws', 'tcp', 'http', 'quic', 'httpupgrade']), None)
        fp = next((s for s in strings if s in ['chrome', 'firefox', 'safari', 'ios', 'edge', '360', 'qq', 'random', 'randomized']), None)

        port = 443
        if server and raw_data is not None:
            # Find server string's byte offset in raw_data (approximate)
            server_bytes = server.encode('ascii', errors='ignore')
            server_idx = raw_data.find(server_bytes)
            if server_idx > -1:
                # Look for little-endian uint16 port 2 bytes before or after server string
                for offset_relative in [-2, len(server_bytes)]:
                    current_offset = server_idx + offset_relative
                    if 0 <= current_offset <= len(raw_data) - 2:
                        try:
                            p = struct.unpack('<H', raw_data[current_offset:current_offset+2])[0]
                            if 0 < p <= 65535:
                                port = p
                                break
                        except struct.error:
                            pass

        if not server or not uuid: # Basic check for valid outbound
            print(f"[parse_sn_link_async] Could not determine server ({server}) or uuid ({uuid}).")
            return None

        tag = tag_str or f'{proto}-{server}'
        out = {
            'type': proto,
            'tag': tag,
            'server': server,
            'server_port': port,
            'uuid': uuid,
            'tls': {
                'enabled': True,
                'server_name': sni or server,
                'utls': {'enabled': True, 'fingerprint': fp or 'chrome'},
            },
            'original_link': url_str # Store original_link here
        }
        if public_key:
            out['tls']['reality'] = {'enabled': True, 'public_key': public_key, 'short_id': short_id or ''}

        if transport:
            out['transport'] = {'type': transport}
            if transport == 'grpc':
                out['transport']['service_name'] = '' # Default

        return out
    except Exception as e:
        print(f'sn:// parse error: {e}')
    return None

def deduplicate_and_tag(outbounds: List[Dict[str, Any]], dedup_enabled: bool = True) -> List[Dict[str, Any]]:
    """
    Deduplicates and assigns unique tags to a list of outbound profiles.
    Translated from JS `deduplicateAndTag`.
    """
    seen_tags = set()
    seen_full_keys = set()
    result = []

    for ob_wrapper in outbounds:
        # Assuming ob_wrapper is {'outbound': ob_dict, 'enabled': True}
        # and ob_dict is the actual outbound configuration
        ob = ob_wrapper['outbound']

        full_key_components = {
            'type': ob.get('type'),
            'server': ob.get('server'),
            'server_port': ob.get('server_port'),
            'uuid': ob.get('uuid'),
            'password': ob.get('password'),
            'method': ob.get('method'),
            'private_key': ob.get('private_key')
        }
        full_key = json.dumps(full_key_components, sort_keys=True)

        if dedup_enabled and full_key in seen_full_keys:
            continue # Skip full duplicates if deduplication is enabled
        seen_full_keys.add(full_key)

        base_tag = ob.get('tag') or ob.get('type') or 'proxy'
        tag = base_tag
        n = 1
        while tag in seen_tags:
            tag = f'{base_tag} ({n})'
            n += 1
        ob['tag'] = tag
        seen_tags.add(tag)

        result.append({'outbound': ob, 'enabled': True})
    return result


def load_profiles(input_data: str, dedup_enabled: bool = True) -> List[Dict[str, Any]]:
    """
    Main function to load and process subscription profiles, translated from JS `loadProfiles`.
    Removes all UI-specific elements and focuses on data processing.

    Args:
        input_data (str): The input string, can be a URL, base64 encoded string,
                          JSON config, or a list of direct links.
        dedup_enabled (bool): Whether to enable deduplication.

    Returns:
        List[Dict[str, Any]]: A list of parsed and deduplicated outbound profiles.
    """

    if not input_data.strip():
        print('Error: Input data is empty.')
        return []

    # --- WireGuard / AmneziaWG .conf (direct input) ---
    if re.search(r'\[Interface\]', input_data, re.IGNORECASE):
        ob = parse_wireguard_conf(input_data, 'wg-conf')
        if ob:
            # For WireGuard configs, we don't have a "link" in the same way,
            # so we'll store the conf_str as 'original_link' if that's desired.
            # Otherwise, these profiles won't be included in a link list output.
            ob['original_link'] = f"[WireGuard Config: {ob.get('tag', 'unknown')}]"
            return deduplicate_and_tag([{'outbound': ob, 'enabled': True}], dedup_enabled)

    links: List[str] = []
    dupe_count = 0 # Local duplicate count for this source

    if input_data.startswith('sn://'):
        print('Decoding sn://...')
        ob = parse_sn_link_async(input_data)
        if not ob:
            print('Error: Invalid sn:// link')
            return []
        # Local deduplication for a single sn:// link
        return deduplicate_and_tag([{'outbound': ob, 'enabled': True}], dedup_enabled)

    if input_data.startswith('http'):
        print('Loading subscription from URL...')
        try:
            # Replaced httpx.Client with urllib.request.urlopen
            with urllib.request.urlopen(input_data, timeout=30) as response:
                text = response.read().decode('utf-8') # Read and decode content
                print(f'Received data ({len(text)/1024:.2f}kb). Decoding...')
                result = decode_subscription(text)
                links = result['links']
                if result['doubleEncoded']:
                    print('Detected double base64, decoded.')
        except urllib.error.HTTPError as e:
            print(f'HTTP error loading subscription: {e.code} - {e.reason}')
            return []
        except urllib.error.URLError as e:
            print(f'Network error loading subscription: {e.reason}')
            return []
        except Exception as e:
            print(f'Error loading subscription: {e}')
            return []
    elif input_data.strip().startswith('{') or input_data.strip().startswith('['):
        print('Parsing JSON config...')
        try:
            outbounds = extract_outbounds_from_config(input_data)
            if outbounds:
                # For JSON configs, we might not have a direct "link".
                # If the outbound object itself can be serialized to a link,
                # that logic would be here. For now, we'll indicate it.
                for ob in outbounds:
                    if 'original_link' not in ob:
                        ob['original_link'] = f"[JSON Config: {ob.get('tag', 'unknown')}]"
                # Local deduplication for JSON config
                return deduplicate_and_tag([{'outbound': ob, 'enabled': True} for ob in outbounds], dedup_enabled)
        except Exception as e:
            print(f'JSON parse error: {e}')
        print('Error: JSON not recognized or no outbounds/endpoints.')
        return []
    elif '://' not in input_data and len(input_data) > 50: # Assume base64 if no protocol and long string
        print('Decoding base64...')
        result = decode_subscription(input_data)
        links = result['links']
        if result['doubleEncoded']:
            print('Detected double base64, decoded.')
    else:
        print('Parsing direct links...')
        links = extract_links(input_data)

    if not links:
        print('Error: No protocols found in input.')
        return []

    print(f'Found {len(links)} links. Parsing...')

    # Sync chunked parsing
    CHUNK = 50
    parsed_profiles_local = [] # Renamed to emphasize local scope
    seen_tags_local = set()     # Renamed
    seen_full_keys_local = set() # Renamed

    for i in range(0, len(links), CHUNK):
        chunk = links[i : i + CHUNK]
        for l in chunk:
            ob = parse_link(l)
            if not ob:
                continue

            full_key_components = {
                'type': ob.get('type'),
                'server': ob.get('server'),
                'server_port': ob.get('server_port'),
                'uuid': ob.get('uuid'),
                'password': ob.get('password'),
                'method': ob.get('method'),
                'private_key': ob.get('private_key')
            }
            full_key = json.dumps(full_key_components, sort_keys=True)

            is_full_dupe = full_key in seen_full_keys_local

            if is_full_dupe:
                dupe_count += 1
                if dedup_enabled:
                    continue # Skip full duplicate
            else:
                seen_full_keys_local.add(full_key)

            # Tag renaming (always, regardless of dedup_enabled)
            base_tag = ob.get('tag') or ''
            tag = base_tag
            n = 1
            while tag in seen_tags_local:
                tag = f'{base_tag} ({n})'
                n += 1
            ob['tag'] = tag
            seen_tags_local.add(tag)

            parsed_profiles_local.append({'outbound': ob, 'enabled': True})

        parsed_so_far = min(i + CHUNK, len(links))
        pct = round(parsed_so_far / len(links) * 100)
        print(f'Parsing: {parsed_so_far} / {len(links)} ({pct}%)')

    # Simplified final message for this internal function
    final_message = f'✓ Processed {len(parsed_profiles_local)} profiles from this source.'
    if dupe_count > 0 and dedup_enabled:
        final_message += f' ({dupe_count} duplicates excluded internally)'
    elif dupe_count > 0 and not dedup_enabled:
        final_message += f' ({dupe_count} duplicates kept internally)'
    print(final_message)

    return parsed_profiles_local


def main():
    # List of URLs to process
    subscription_urls = [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
        "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
        "http://invalid.url/test.txt", # An example of an invalid URL
    ]

    validated_urls = []
    print("--- Validating Subscription URLs ---")
    # Replaced httpx.Client with urllib.request.urlopen
    for url in subscription_urls:
        try:
            print(f"Checking URL: {url}...")
            # Use HEAD request to check if URL is accessible without downloading content
            req = urllib.request.Request(url, method='HEAD') # Create a Request object for HEAD
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200: # Check status
                    validated_urls.append(url)
                    print(f"  ✓ Valid URL: {url}")
                else:
                    print(f"  ✗ Invalid URL (Status {response.status}): {url}")
        except urllib.error.HTTPError as e:
            print(f"  ✗ HTTP error for {url}: Status {e.code}") # Access status code
        except urllib.error.URLError as e:
            print(f"  ✗ Network error for {url}: {e.reason}") # Access reason for URL error
        except Exception as e:
            print(f"  ✗ An unexpected error occurred for {url}: {e}")

    if not validated_urls:
        print("No valid subscription URLs found to process. Exiting.")
        return

    print(f"\n--- Processing {len(validated_urls)} Valid URL Subscriptions ---")

    all_collected_profiles: List[Dict[str, Any]] = []

    for url in validated_urls:
        print(f"Loading profiles from: {url}")
        profiles_from_url = load_profiles(url, dedup_enabled=True)
        all_collected_profiles.extend(profiles_from_url)
        print(f"  Added {len(profiles_from_url)} profiles from {url}. Total collected: {len(all_collected_profiles)}")
        print("-" * 30)

    print("\n--- Performing Global Deduplication and Tagging ---")
    final_deduplicated_profiles = deduplicate_and_tag(all_collected_profiles, dedup_enabled=True)

    initial_count = len(all_collected_profiles)
    final_count = len(final_deduplicated_profiles)
    duplicates_removed_globally = initial_count - final_count

    print(f"Initial profiles collected (before global deduplication): {initial_count}")
    print(f"Final deduplicated profiles: {final_count}")
    if duplicates_removed_globally > 0:
        print(f"Globally removed {duplicates_removed_globally} duplicate profiles.")
    else:
        print("No further global duplicates found.")

    print("\n--- Saving Final Profiles to File ---")
    output_filename = 'final_subscriptions.txt'
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            for profile_wrapper in final_deduplicated_profiles:
                outbound = profile_wrapper['outbound']
                original_link = outbound.get('original_link')
                if original_link and not original_link.startswith('[WireGuard Config:') and not original_link.startswith('[JSON Config:') and not original_link.startswith('[AmneziaWG Config:') : # Added check for AmneziaWG
                    f.write(original_link + '\n')
                else:
                    # For WireGuard/JSON profiles, or any without a resolvable original_link,
                    # you might decide to print their tag or skip them from this specific output.
                    # For now, we'll just print a warning.
                    print(f"Warning: 'original_link' is not a direct subscription link for profile: {outbound.get('tag', 'unknown')}. Skipping this entry from .txt file.")
        print(f"Successfully saved {len(final_deduplicated_profiles)} direct subscription links to {output_filename}")
    except Exception as e:
        print(f"Error saving profiles to file: {e}")


if __name__ == '__main__':
    main()
