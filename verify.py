import sys, re, json, hashlib, hmac

KEY = b"demo-device-key"
expected_prev = "00" * 32          # genesis
good = bad = 0

for line in open(sys.argv[1], encoding="utf-8", errors="ignore"):
    m = re.search(r"REC (\{.*\})", line)
    if not m:
        continue
    try:
        r = json.loads(m.group(1))
    except ValueError:
        print("UNREADABLE record (line broken?)")
        bad += 1
        continue

    seq = r["body"].split("|")[1]
    problems = []

    if r["prev"] != expected_prev:
        problems.append("chain broken (record missing or reordered)")

    h = hashlib.sha256(bytes.fromhex(r["prev"]) + r["body"].encode()).digest()
    if h.hex() != r["hash"]:
        problems.append("data was modified (hash mismatch)")

    s = hmac.new(KEY, bytes.fromhex(r["hash"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(s, r["sig"]):
        problems.append("signature invalid")

    if problems:
        bad += 1
        print(f"seq {seq}: TAMPER DETECTED -> " + "; ".join(problems))
    else:
        good += 1
        print(f"seq {seq}: OK")

    expected_prev = r["hash"]

print(f"\n{good} valid, {bad} problem records")