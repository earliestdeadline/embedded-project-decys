import math, collections

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())

# Load the firmware dump
with open('../target-2/memory_dumps/memory_0.bin', 'rb') as f:
    buf = f.read()

window = 256   # bytes per window
step = 256     # how far to slide each time

# Full scan across the file
print(f"{'offset':>8}  {'entropy(bits/byte)':>20}")
for off in range(0, len(buf), step):
    chunk = buf[off:off+window]
    if len(chunk) < 16:
        continue
    print(f"{off:>8}  {shannon_entropy(chunk):>20.3f}")

# Find and measure specific regions by their known content
menu_idx = buf.find(b'DEVELOPMENT MENU')
print("code/menu region:", shannon_entropy(buf[menu_idx-128:menu_idx+128]))

eula_idx = buf.find(b'END USER LICENSE')
print("plain English region:", shannon_entropy(buf[eula_idx:eula_idx+256]))

key_idx = buf.find(b'MIIEowIBAAKCAQEA')   # start of the base64 key text
print("base64 key region:", shannon_entropy(buf[key_idx:key_idx+256]))

# Compare against the *decoded* raw key bytes (from the earlier base64 -d step)
with open('key.der', 'rb') as f:
    der = f.read()
print("decoded raw key bytes:", shannon_entropy(der))