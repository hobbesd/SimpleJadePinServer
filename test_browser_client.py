"""Jade-side helper for test_browser.js (same wally primitives as test_protocol.py).

Keeps one simulated wallet in a JSON state file:
    init    <statefile> <server pubkey hex>    create a wallet (PIN key, PIN secret)
    setpin  <base url> <statefile>             real set_pin over HTTP, remembers the key
    getpin  <base url> <statefile>             real get_pin over HTTP, prints the key
    prepare <set_pin|get_pin> <statefile>      prints the request data a Jade would put into its QR codes
    verify  <statefile> <reply base64>         decrypts a server reply, prints the key
"""
import base64, json, os, sys, urllib.request
from hashlib import sha256
import wallycore as wally

def load(p): return json.load(open(p)) if os.path.exists(p) else {}
def save(p, d): json.dump(d, open(p, "w"))

def build(st, func, srv_pub_hex):
    client_priv = bytearray(os.urandom(32)); wally.ec_private_key_verify(client_priv)
    cke = wally.ec_public_key_from_private_key(client_priv)
    st["ctr"] = st.get("ctr", 0) + 1
    replay = st["ctr"].to_bytes(4, "little")
    pin_priv = bytearray(bytes.fromhex(st["pin_priv"])); pin_secret = bytes.fromhex(st["pin_secret"])
    if func == "set_pin":
        entropy = os.urandom(32)
        msg = bytearray(sha256(bytes(cke) + replay + pin_secret + entropy).digest()); payload = pin_secret + entropy
    else:
        msg = bytearray(sha256(bytes(cke) + replay + pin_secret).digest()); payload = pin_secret
    sig = wally.ec_sig_from_bytes(pin_priv, msg, wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE)
    tweak = sha256(wally.hmac_sha256(cke, replay)).digest()
    srv_pub = wally.ec_public_key_bip341_tweak(bytearray(bytes.fromhex(srv_pub_hex)), tweak, 0)
    enc = wally.aes_cbc_with_ecdh_key(client_priv, os.urandom(16), payload + bytes(sig), srv_pub, b'blind_oracle_request', wally.AES_FLAG_ENCRYPT)
    st["client_priv"] = bytes(client_priv).hex(); st["srv_pub_tweaked"] = bytes(srv_pub).hex()
    return base64.b64encode(bytes(cke) + replay + bytes(enc)).decode()

def decrypt(st, reply_b64):
    return bytes(wally.aes_cbc_with_ecdh_key(bytearray(bytes.fromhex(st["client_priv"])), None, base64.b64decode(reply_b64),
                 bytearray(bytes.fromhex(st["srv_pub_tweaked"])), b'blind_oracle_response', wally.AES_FLAG_DECRYPT)).hex()

cmd = sys.argv[1]
if cmd == "init":
    statefile, srv_pub_hex = sys.argv[2], sys.argv[3]
    pin_priv = bytearray(os.urandom(32)); wally.ec_private_key_verify(pin_priv)
    save(statefile, {"pin_priv": bytes(pin_priv).hex(), "pin_secret": os.urandom(32).hex(), "srv_pub": srv_pub_hex})
elif cmd == "prepare":
    func, statefile = sys.argv[2], sys.argv[3]
    st = load(statefile); data = build(st, func, st["srv_pub"]); save(statefile, st); print(data)
elif cmd == "verify":
    st = load(sys.argv[2]); print(decrypt(st, sys.argv[3]))
elif cmd == "setpin":
    base, statefile = sys.argv[2], sys.argv[3]
    st = load(statefile); data = build(st, "set_pin", st["srv_pub"])
    req = urllib.request.Request(base + "/set_pin", data=json.dumps({"data": data}).encode(), method="POST")
    reply = json.loads(urllib.request.urlopen(req, timeout=10).read())["data"]
    st["key"] = decrypt(st, reply); save(statefile, st); print(st["key"])
elif cmd == "getpin":
    base, statefile = sys.argv[2], sys.argv[3]
    st = load(statefile); data = build(st, "get_pin", st["srv_pub"])
    req = urllib.request.Request(base + "/get_pin", data=json.dumps({"data": data}).encode(), method="POST")
    reply = json.loads(urllib.request.urlopen(req, timeout=10).read())["data"]
    save(statefile, st); print(decrypt(st, reply))
