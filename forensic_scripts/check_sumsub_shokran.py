with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
    strings = [line.strip() for line in f]

sumsub_ctx = []
shokran_ctx = []

for i, s in enumerate(strings):
    if 'sumsub' in s.lower():
        sumsub_ctx.extend(strings[max(0, i-5):min(len(strings), i+6)])
    if 'shokran' in s.lower():
        shokran_ctx.extend(strings[max(0, i-5):min(len(strings), i+6)])

print("=== SumSub Context ===")
for s in set(sumsub_ctx):
    print("  *", s)

print("\n=== Shokran Wallet Context ===")
for s in set(shokran_ctx):
    print("  *", s)
