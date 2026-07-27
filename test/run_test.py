import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
sys.path.insert(0, '.')
from pipelines.aadhaar import verify_aadhaar

result = verify_aadhaar(
    'EAadhaar_0000003383820320250526144720_200620261751.pdf',
    'LILE2001'
)

print('=== CHECKS ===')
for c in result.get('checks', []):
    if c['passed']:
        status = 'PASS'
    elif c.get('warning'):
        status = 'WARN'
    else:
        status = 'FAIL'
    print(f"  [{status}] {c['name']}: {c['detail']}")

print()
print('=== QR DATA ===')
qr = result.get('qr_data', {})
for k, v in qr.items():
    if k not in ('signed_data', 'signature', 'raw_decoded') and not isinstance(v, bytes):
        print(f"  {k}: {v}")

print()
print('=== VERDICT INPUTS ===')
print(f"  signature_valid: {result.get('signature_valid')}")
print(f"  fields_match: {result.get('fields_match')}")
print(f"  error: {result.get('error', 'None')}")
