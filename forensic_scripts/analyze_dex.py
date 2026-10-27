import struct
import re

def analyze_dex(dex_path):
    with open(dex_path, 'rb') as f:
        data = f.read()

    magic = data[:8]
    print(f"DEX Magic: {magic}")
    
    file_size = struct.unpack('<I', data[32:36])[0]
    string_ids_size = struct.unpack('<I', data[56:60])[0]
    string_ids_off = struct.unpack('<I', data[60:64])[0]
    type_ids_size = struct.unpack('<I', data[64:68])[0]
    type_ids_off = struct.unpack('<I', data[68:72])[0]
    proto_ids_size = struct.unpack('<I', data[72:76])[0]
    proto_ids_off = struct.unpack('<I', data[76:80])[0]
    field_ids_size = struct.unpack('<I', data[80:84])[0]
    field_ids_off = struct.unpack('<I', data[84:88])[0]
    method_ids_size = struct.unpack('<I', data[88:92])[0]
    method_ids_off = struct.unpack('<I', data[92:96])[0]
    class_defs_size = struct.unpack('<I', data[96:100])[0]
    class_defs_off = struct.unpack('<I', data[100:104])[0]

    print(f"String count: {string_ids_size}")
    print(f"Type count: {type_ids_size}")
    print(f"Method count: {method_ids_size}")
    print(f"Class count: {class_defs_size}")

    # Extract strings
    strings = []
    for i in range(string_ids_size):
        str_off = struct.unpack('<I', data[string_ids_off + 4*i : string_ids_off + 4*i + 4])[0]
        # read uleb128 length
        p = str_off
        length = 0
        shift = 0
        while True:
            b = data[p]
            p += 1
            length |= (b & 0x7f) << shift
            shift += 7
            if not (b & 0x80):
                break
        # read utf-8 bytes up to null terminator
        null_pos = data.find(b'\x00', p)
        if null_pos != -1:
            s_bytes = data[p:null_pos]
            try:
                s = s_bytes.decode('utf-8')
            except:
                s = s_bytes.decode('latin1', errors='replace')
            strings.append(s)
        else:
            strings.append("")

    # Extract types
    types = []
    for i in range(type_ids_size):
        descriptor_idx = struct.unpack('<I', data[type_ids_off + 4*i : type_ids_off + 4*i + 4])[0]
        if descriptor_idx < len(strings):
            types.append(strings[descriptor_idx])
        else:
            types.append(f"Type_{descriptor_idx}")

    # Extract class defs
    classes = []
    for i in range(class_defs_size):
        class_idx = struct.unpack('<I', data[class_defs_off + 32*i : class_defs_off + 32*i + 4])[0]
        if class_idx < len(types):
            classes.append(types[class_idx])

    return strings, types, classes

strings, types, classes = analyze_dex(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex')

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_classes.txt', 'w', encoding='utf-8') as f:
    for c in classes:
        f.write(c + '\n')

print(f"Saved {len(classes)} classes to all_classes.txt")

# Let's inspect class packages
package_counts = {}
for c in classes:
    # Lcom/example/MyClass; -> com.example
    clean = c.lstrip('L').rstrip(';')
    parts = clean.split('/')
    if len(parts) > 1:
        pkg = ".".join(parts[:-1])
    else:
        pkg = "default"
    # group by top 2 or 3 parts
    top_pkg = ".".join(pkg.split('.')[:3])
    package_counts[top_pkg] = package_counts.get(top_pkg, 0) + 1

print("\n--- Top Package Prefixes ---")
for pkg, count in sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:30]:
    print(f"{pkg}: {count} classes")

# Search for suspicious strings/indicators
suspicious_patterns = [
    r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?',
    r'eval\(',
    r'/system/bin/su',
    r'/system/xbin/su',
    r'Superuser',
    r'chmod\s+777',
    r'getDeviceId',
    r'getSubscriberId',
    r'getSimSerialNumber',
    r'sendTextMessage',
    r'readSms',
    r'ACCESS_FINE_LOCATION',
    r'DexClassLoader',
    r'dalvik\.system',
    r'Runtime\.getRuntime\(\)\.exec',
    r'killProcess',
    r'crypto',
    r'tor2web',
    r'onion',
    r'botnet',
    r'rat',
    r'spy',
    r'stealer',
    r'trojan',
    r'exploit',
    r'ransom',
    r'payload',
    r'pairip'
]

urls = set()
url_regex = re.compile(r'https?://[^\s\'"<>]+')
for s in strings:
    found_urls = url_regex.findall(s)
    for u in found_urls:
        urls.add(u)

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted_urls.txt', 'w', encoding='utf-8') as f:
    for u in sorted(urls):
        f.write(u + '\n')

print(f"\nExtracted {len(urls)} distinct URLs saved to extracted_urls.txt")
