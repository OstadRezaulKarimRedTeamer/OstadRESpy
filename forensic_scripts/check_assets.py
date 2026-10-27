import os
import zipfile
import math

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

apk_path = r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\base.apk'
with zipfile.ZipFile(apk_path, 'r') as z:
    infolist = z.infolist()
    print(f"Total entries in APK: {len(infolist)}")
    
    suspicious_files = []
    large_files = []
    
    for info in infolist:
        name = info.filename
        size = info.file_size
        
        # Check extensions
        ext = os.path.splitext(name)[1].lower()
        if ext in ['.exe', '.dll', '.so', '.bin', '.sh', '.bat', '.cmd', '.vbs', '.js', '.jar', '.apk', '.dex']:
            if name != 'classes.dex' and name != 'DebugProbesKt.bin':
                suspicious_files.append((name, size))
                
        if size > 100000: # > 100KB
            large_files.append((name, size))

    print("\nSuspicious or binary extensions (excluding classes.dex):")
    if not suspicious_files:
        print("  None!")
    else:
        for f, s in suspicious_files:
            print(f"  {f} ({s} bytes)")

    print("\nFiles larger than 100KB:")
    for f, s in large_files:
        data = z.read(f)
        ent = shannon_entropy(data)
        print(f"  {f}: {s} bytes, Entropy: {ent:.2f}")

