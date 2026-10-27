import re

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
    strings = [line.strip() for line in f]

# Find all API paths, endpoints, and JSON keys
api_paths = []
json_fields = []
headers = []

for s in strings:
    # API endpoints
    if s.startswith('/') and len(s) > 2 and not s.startswith('/system') and not s.startswith('/data') and not s.startswith('/android'):
        if any(keyword in s.lower() for keyword in ['api', 'v1', 'v2', 'auth', 'user', 'post', 'feed', 'login', 'token', 'register', 'profile', 'comment', 'message', 'chat', 'notification']):
            api_paths.append(s)
    
    # HTTP headers
    if any(h in s.lower() for h in ['authorization', 'bearer', 'user-agent', 'x-api-key', 'device-id', 'device_id', 'client-id']):
        headers.append(s)

print("=== Discovered API Endpoints & Paths ===")
for p in sorted(list(set(api_paths))):
    print("  ", p)

print("\n=== Discovered Auth / Tracking Headers ===")
for h in sorted(list(set(headers)))[:30]:
    print("  ", h)
