import json
import paho.mqtt.publish as publish

TOPIC = "coldchain/9w7tzbxemrsf/CC-0001/records"
fake = {"body": "CC-0001|9999|1|5.00|5.00|0|1000|0.00|OK|none|-1|5.00|rules-v1",
        "prev": "00" * 32, "hash": "11" * 32, "sig": "22" * 32}
publish.single(TOPIC, json.dumps(fake), hostname="broker.hivemq.com")   # your broker
print("Forged record sent")