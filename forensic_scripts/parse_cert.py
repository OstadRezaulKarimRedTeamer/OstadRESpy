import struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\base.apk', 'rb') as f:
    data = f.read()

# EOCD
eocd_pos = data.rfind(b'\x50\x4b\x05\x06')
cd_size, cd_offset = struct.unpack('<II', data[eocd_pos+12:eocd_pos+20])
footer = data[cd_offset-24:cd_offset]
block_size = struct.unpack('<Q', footer[:8])[0]
block_start = cd_offset - block_size - 8

p = block_start + 8
while p < cd_offset - 24:
    pair_len = struct.unpack('<Q', data[p:p+8])[0]
    pair_id = struct.unpack('<I', data[p+8:p+12])[0]
    pair_data = data[p+12:p+8+pair_len]
    if pair_id == 0x7109871a: # v2 scheme
        # parse signers
        signers_len = struct.unpack('<I', pair_data[:4])[0]
        # signer 1
        signer_len = struct.unpack('<I', pair_data[4:8])[0]
        signer = pair_data[8:8+signer_len]
        
        # signed data
        signed_data_len = struct.unpack('<I', signer[:4])[0]
        signed_data = signer[4:4+signed_data_len]
        
        # digets
        digests_len = struct.unpack('<I', signed_data[:4])[0]
        # certificates
        certs_offset = 4 + digests_len
        certs_len = struct.unpack('<I', signed_data[certs_offset:certs_offset+4])[0]
        
        cert_p = certs_offset + 4
        while cert_p < certs_offset + 4 + certs_len:
            cert_len = struct.unpack('<I', signed_data[cert_p:cert_p+4])[0]
            cert_der = signed_data[cert_p+4:cert_p+4+cert_len]
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            print("=== Certificate Info ===")
            print(f"Subject: {cert.subject.rfc4514_string()}")
            print(f"Issuer: {cert.issuer.rfc4514_string()}")
            print(f"Serial: {hex(cert.serial_number)}")
            print(f"Not Before: {cert.not_valid_before_utc}")
            print(f"Not After: {cert.not_valid_after_utc}")
            print(f"SHA256 Fingerprint: {cert.fingerprint(cert.signature_hash_algorithm).hex()}")
            cert_p += 4 + cert_len
    p += 8 + pair_len
