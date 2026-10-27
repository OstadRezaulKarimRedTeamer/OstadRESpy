import re

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
    strings = [line.strip() for line in f]

tracker_patterns = {
    "Google / Firebase Analytics": ["firebase_analytics", "google-analytics", "ga_trackingId", "app_measurement", "FirebaseAnalytics"],
    "Facebook SDK": ["com.facebook.sdk", "facebook.com", "FacebookSdk", "AppEventsLogger", "com.facebook.appevents"],
    "Adjust / AppsFlyer / Branch": ["com.adjust.sdk", "com.appsflyer", "io.branch", "appsflyer.com", "adjust.com"],
    "Mixpanel / Amplitude / Segment": ["com.mixpanel", "amplitude", "segment.io", "com.segment"],
    "Ad Networks": ["admob", "unity3d.ads", "applovin", "ironsource", "mopub", "vungle", "chartboost"],
    "Crashlytics": ["crashlytics", "com.google.firebase.crashlytics"],
    "SumSub (KYC Verification)": ["sumsub", "sns_applicant", "idensic"],
    "Shokran Wallet (Fintech)": ["shokran", "wallet.shokran"],
    "Identity / Device ID Trackers": [
        "ANDROID_ID", "getDeviceId", "getImei", "getSubscriberId", "getSimSerialNumber",
        "getMacAddress", "AdvertisingIdClient", "advertising_id", "getSSID", "getBSSID"
    ]
}

print("=== Tracker & Data Exfiltration Search ===")
for category, keywords in tracker_patterns.items():
    print(f"\n--- {category} ---")
    matches = set()
    for kw in keywords:
        for s in strings:
            if kw.lower() in s.lower():
                matches.add(s)
    if not matches:
        print("  None detected.")
    else:
        for m in sorted(list(matches))[:10]:
            print(f"  * {m[:120]}")
        if len(matches) > 10:
            print(f"  ... and {len(matches)-10} more matches.")
