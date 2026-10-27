import struct
import hashlib

def check_apk_signing_block(apk_path):
    with open(apk_path, 'rb') as f:
        data = f.read()

    # Find End of Central Directory (EOCD)
    eocd_pos = data.rfind(b'\x50\x4b\x05\x06')
    if eocd_pos == -1:
        print("EOCD not found")
        return

    cd_size, cd_offset = struct.unpack('<II', data[eocd_pos+12:eocd_pos+20])
    print(f"Central Directory offset: {cd_offset}, size: {cd_size}")

    # Check for APK Signing Block just before CD
    # Format of footer: size (8 bytes), magic (16 bytes: "APK Sig Block 42")
    footer = data[cd_offset-24:cd_offset]
    magic = footer[8:24]
    if magic == b'APK Sig Block 42':
        block_size = struct.unpack('<Q', footer[:8])[0]
        block_start = cd_offset - block_size - 8
        print(f"APK Signing Block found! Size: {block_size} bytes, Start: {block_start}")
        
        # Parse ID-value pairs in signing block
        p = block_start + 8
        while p < cd_offset - 24:
            pair_len = struct.unpack('<Q', data[p:p+8])[0]
            pair_id = struct.unpack('<I', data[p+8:p+12])[0]
            pair_data = data[p+12:p+8+pair_len]
            print(f"  Found ID: {hex(pair_id)} (Length: {pair_len})")
            if pair_id == 0x7109871a:
                print("    -> APK Signature Scheme v2 Block")
            elif pair_id == 0xf05368c0:
                print("    -> APK Signature Scheme v3 Block")
            elif pair_id == 0x2b091894:
                print("    -> Google Play App Signing / Stamp Block (v1/v2/v3)")
            p += 8 + pair_len
    else:
        print(f"No APK Signing Block footer: {magic}")

check_apk_signing_block(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\base.apk')
