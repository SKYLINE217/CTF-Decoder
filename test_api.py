import urllib.request, json, base64

r = urllib.request.urlopen('http://127.0.0.1:8000/api/codecs')
d = json.loads(r.read())
print("Codecs loaded:", len(d["codecs"]))

payload = json.dumps({"data_b64": base64.b64encode(b"cGljb0NURnt3ZWJfdWlfZmxhZ30=").decode()})
req = urllib.request.Request(
    "http://127.0.0.1:8000/api/decode",
    data=payload.encode(),
    headers={"Content-Type": "application/json"}
)
r = urllib.request.urlopen(req)
d = json.loads(r.read())
print("Decode success:", d["success"])
print("Output:", d.get("final_output_str"))
print("Flags:", [f["value"] for f in d.get("flags", [])])
print("Score:", d.get("score", {}).get("total"))

r = urllib.request.urlopen("http://127.0.0.1:8000/api/memory")
d = json.loads(r.read())
print("Memory priors:", len(d["priors"]))
print("Templates:", len(d["templates"]))
