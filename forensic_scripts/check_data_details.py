import re

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
    strings = [line.strip() for line in f]

# Search strings around device registration
dev_strings = []
for i, s in enumerate(strings):
    if '/devices' in s or 'fcm_token' in s.lower() or 'push_token' in s.lower() or 'devicetoken' in s.lower():
        dev_strings.extend(strings[max(0, i-10):min(len(strings), i+15)])

print("=== Device Registration Context ===")
for s in set(dev_strings):
    if any(k in s.lower() for k in ['token', 'device', 'model', 'os', 'version', 'id', 'fcm', 'push', 'platform']):
        print("  *", s)

# Search location usage
loc_strings = []
for i, s in enumerate(strings):
    if any(k in s.lower() for k in ['latitude', 'longitude', 'fusedlocation', 'prayer_times', 'qibla', 'open-meteo']):
        loc_strings.extend(strings[max(0, i-5):min(len(strings), i+6)])

print("\n=== Location Usage Context ===")
for s in set(loc_strings):
    if any(k in s.lower() for k in ['lat', 'lon', 'prayer', 'qibla', 'meteo', 'location', 'city', 'country']):
        print("  *", s)
