import json, hashlib, hmac
import paho.mqtt.client as mqtt

KEY   = b"demo-device-key"  # DEMO KEY ONLY: a real device would keep keys in secure storage
HOST, PORT = "broker.hivemq.com", 1883      # keep the broker that works for you
TOPIC = "coldchain/9w7tzbxemrsf/CC-0001/records"

expected_prev = None
expected_seq  = None
logfile = open("live_log.txt", "w", encoding="utf-8")

def check(raw):
    global expected_prev, expected_seq
    r = json.loads(raw)
    body = r["body"].split("|")
    seq = int(body[1])
    f = lambda i, d="-": body[i] if len(body) > i else d
    problems = []

    if seq == 0 and r["prev"] == "00" * 32:
        if expected_seq is not None:
            print(">>> device restarted: new chain")
        expected_prev, expected_seq = r["prev"], 0
    elif expected_prev is None:
        print(">>> joined mid-stream, trusting this record's prev")
        expected_prev, expected_seq = r["prev"], seq

    if seq != expected_seq:
        problems.append(f"sequence gap (expected {expected_seq})")
    if r["prev"] != expected_prev:
        problems.append("chain broken")

    h = hashlib.sha256(bytes.fromhex(r["prev"]) + r["body"].encode()).digest()
    if h.hex() != r["hash"]:
        problems.append("data modified (hash mismatch)")
    s = hmac.new(KEY, bytes.fromhex(r["hash"]), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(s, r["sig"]):
        problems.append("signature invalid")

    label = (f"seq {seq:>4}  t_in={f(3):>6}  t_out={f(4):>6}  {f(8):<9} "
             f"{f(9):<18} eta={f(10):>4}  mkt={f(11):>6}")
    if problems:
        print(label, "-> TAMPER/ERROR:", "; ".join(problems))
    else:
        print(label, "-> OK")
        expected_prev, expected_seq = r["hash"], seq + 1

def on_connect(client, userdata, *args):
    client.subscribe(TOPIC)
    print("Connected, waiting for records...")

def on_message(client, userdata, msg):
    raw = msg.payload.decode(errors="ignore")
    try:
        check(raw)
        logfile.write("REC " + raw + "\n"); logfile.flush()
    except Exception as e:
        print("Unreadable message:", e)

try:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
except AttributeError:
    c = mqtt.Client()
c.on_connect = on_connect
c.on_message = on_message
c.connect(HOST, PORT)
c.loop_forever()