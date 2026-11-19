#!/usr/bin/env python3
"""End-to-end protocol test for SimpleJadePinServer.

Simulates a Jade client with the same wally primitives against a live server
instance (fresh throwaway key_data — NEVER run against real key_data).
Manages the server process itself (needed for the restart-persistence test):

    docker run --rm -v .../test_protocol.py:/app/test_protocol.py:ro \
        --entrypoint python3 <image> /app/test_protocol.py

Covers: set_pin, set_pin replay rejection (upstream parity), correct get_pin,
wrong-pin counter + replay advance on failed attempts, counter reset, two
wrong attempts do NOT wipe, restart persistence, corrupt pin file handling,
3-strikes wipe, blind semantics (post-wipe and never-seen wallet), malformed
requests, oversized body, origin check, and the exact format of the server's
security event lines (the alert contract) including log-injection resistance.
Also: file permissions, key-file sanity checks at start-up (permissions,
public/private mismatch, invalid key), the pin file limit, response security
headers, static assets and caching, and TLS mode (a silent client must not
block other clients).

NOTE: client mirrors the server's constructions (tweak derivation, labels,
payload layout) — a shared deviation from the real Jade protocol would not be
caught here. The device-compatibility anchor is the real Jade pairing.
"""
from hashlib import sha256
import base64
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import wallycore as wally

BASE = "http://127.0.0.1:4443"
SERVER_LOG = "test_server.log"

SERVER_PUBKEY = None  # set in main from key_data
server_proc = None
log_fh = None

# The alert contract: exact event line formats an external watcher anchors on.
RE_WRONG = re.compile(r"^Wrong pin \(([123])\. attempt\) \[wallet ([0-9a-f]{8})\]$")
RE_WIPE = re.compile(r"^Too many wrong attempts \[wallet ([0-9a-f]{8})\]$")
RE_CORRECT = re.compile(r"^Correct pin on the ([123])\. attempt \[wallet ([0-9a-f]{8})\]$")
RE_STORED = re.compile(r"^New pin stored \[wallet ([0-9a-f]{8})\]$")
RE_NEWKEY = re.compile(r"^WARNING: NEW STATIC SERVER KEY GENERATED")
RE_PINS_MISSING = re.compile(r"^NOTICE: pins directory missing")
RE_REPLAY = re.compile(r"^Replay rejected \[wallet ([0-9a-f]{8})\]$")
RE_DAMAGED = re.compile(r"^Pin file damaged \[wallet ([0-9a-f]{8})\]$")
RE_UNKNOWN = re.compile(r"^Unknown wallet \[wallet ([0-9a-f]{8})\]$")
RE_LIMIT = re.compile(r"^Pin limit reached \[wallet ([0-9a-f]{8})\]$")
RE_PUBKEY = re.compile(r"^Static server public key: ([0-9a-f]{66})$")
RE_MISMATCH = re.compile(r"^WARNING: PUBLIC KEY MISMATCH")
RE_PERMS = re.compile(r"^NOTICE: private\.key was accessible to other users \(mode 0644\), tightened to 0600$")
RE_BADKEY = re.compile(r"^ERROR: .*private\.key is not a valid private key")
RE_CONN_ERROR = re.compile(r"^Connection error: [A-Za-z]+$")
ALL_EVENTS = (RE_WRONG, RE_WIPE, RE_CORRECT, RE_STORED, RE_NEWKEY, RE_PINS_MISSING, RE_REPLAY,
              RE_DAMAGED, RE_UNKNOWN, RE_LIMIT, RE_PUBKEY, RE_MISMATCH, RE_PERMS, RE_BADKEY)

TLS_PORT = 4444

# Self-signed certificate for the TLS-mode test only. This key pair is public
# (it is printed right here) and protects nothing; it merely lets the test
# start the server in TLS mode without needing an openssl binary.
TEST_TLS_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEZzgZ0Alc3BfbePM
KfVWwhVb1FNZ2Muc5jGURbTYdeGhRANCAAT4FDazxtVCnA5Yxy9FYtYWFmbQ/Fzd
R7JsYT4gqsCH5JC2YnhTFr67UGK2To2DMv1WVxkkvSVDCUtd9aTgMfP5
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIBvzCCAWWgAwIBAgIUPA1artWXNqYk0qB36kDDka9DEz0wCgYIKoZIzj0EAwIw
PDE6MDgGA1UEAwwxU2ltcGxlSmFkZVBpblNlcnZlciB0ZXN0IGNlcnRpZmljYXRl
IChub3Qgc2VjcmV0KTAgFw0yNjExMTYyMDUxNTdaGA8yMTI2MTAyMzIwNTE1N1ow
PDE6MDgGA1UEAwwxU2ltcGxlSmFkZVBpblNlcnZlciB0ZXN0IGNlcnRpZmljYXRl
IChub3Qgc2VjcmV0KTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPgUNrPG1UKc
DljHL0Vi1hYWZtD8XN1HsmxhPiCqwIfkkLZieFMWvrtQYrZOjYMy/VZXGSS9JUMJ
S131pOAx8/mjQzBBMB0GA1UdDgQWBBTzOueZ4baoLgfda0mvdHoZokUnRzAPBgNV
HRMBAf8EBTADAQH/MA8GA1UdEQQIMAaHBH8AAAEwCgYIKoZIzj0EAwIDSAAwRQIh
AO+tsxhuXDb3Uv5cxwbrIY9r5igWDgJk9vhPpHMzBKG0AiAyNP9yRV6IFe3+jTGe
6mJ5Jnid8w00eXhSqQUS9XYoTw==
-----END CERTIFICATE-----
"""


def start_server(args=("--no-tls",), env=None, port=4443):
    global server_proc, log_fh
    log_fh = open(SERVER_LOG, "ab")
    full_env = dict(os.environ)
    full_env.update(env or {})
    server_proc = subprocess.Popen([sys.executable, "SimpleJadePinServer.py", *args],
                                   stdout=log_fh, stderr=subprocess.STDOUT, env=full_env)

    for _ in range(50):
        if server_proc.poll() is not None:
            break

        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.2)

    raise RuntimeError("server did not come up")


def run_server_expect_exit(args=("--no-tls",), env=None):
    """Start the server where it is expected to refuse to run; return its exit code."""
    full_env = dict(os.environ)
    full_env.update(env or {})
    with open(SERVER_LOG, "ab") as fh:
        proc = subprocess.Popen([sys.executable, "SimpleJadePinServer.py", *args],
                                stdout=fh, stderr=subprocess.STDOUT, env=full_env)
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            return None


def stop_server():
    server_proc.terminate()
    server_proc.wait(timeout=10)
    log_fh.close()


def server_log_lines():
    if log_fh is not None and not log_fh.closed:
        log_fh.flush()
    with open(SERVER_LOG, "rb") as f:
        return f.read().decode("utf-8", "replace").splitlines()


def count_matches(regex):
    return sum(1 for line in server_log_lines() if regex.match(line))


def event_groups(regex):
    """First capture group of every log line matching the event regex, in order."""
    return [m.group(1) for m in (regex.match(line) for line in server_log_lines()) if m]


def file_mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def get(path, headers=None, base=None, context=None, timeout=10):
    """GET -> (status, headers with lower-case names, body)."""
    req = urllib.request.Request((base or BASE) + path, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def post(path, body, timeout=10, headers=None, base=None, context=None):
    st, _, resp = post_with_headers(path, body, timeout, headers, base, context)
    return st, resp


def post_with_headers(path, body, timeout=10, headers=None, base=None, context=None):
    h = {"Content-Type": "application/json"}

    if headers:
        h.update(headers)

    req = urllib.request.Request((base or BASE) + path, data=body.encode(), method="POST",
                                 headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def tweaked_server_pubkey(cke, replay_counter):
    tweak = sha256(wally.hmac_sha256(cke, replay_counter)).digest()
    return wally.ec_public_key_bip341_tweak(SERVER_PUBKEY, tweak, 0)


def make_request(func, pin_privkey, pin_secret, replay_counter, entropy=None):
    client_priv = bytearray(os.urandom(32))
    wally.ec_private_key_verify(client_priv)
    cke = wally.ec_public_key_from_private_key(client_priv)

    if func == "set_pin":
        msg = bytearray(sha256(bytes(cke) + replay_counter + pin_secret + entropy).digest())
        payload = pin_secret + entropy
    else:
        msg = bytearray(sha256(bytes(cke) + replay_counter + pin_secret).digest())
        payload = pin_secret

    sig = wally.ec_sig_from_bytes(pin_privkey, msg,
                                  wally.EC_FLAG_ECDSA | wally.EC_FLAG_RECOVERABLE)
    payload = payload + bytes(sig)

    srv_pub = tweaked_server_pubkey(cke, replay_counter)
    encrypted = wally.aes_cbc_with_ecdh_key(client_priv, os.urandom(16), payload,
                                            srv_pub, b'blind_oracle_request',
                                            wally.AES_FLAG_ENCRYPT)
    data = bytes(cke) + replay_counter + bytes(encrypted)
    body = json.dumps({"data": base64.b64encode(data).decode()})
    status, resp = post("/" + func, body)

    if status != 200:
        return status, None

    resp_data = base64.b64decode(json.loads(resp)["data"])
    aes_key = wally.aes_cbc_with_ecdh_key(client_priv, None, resp_data, srv_pub,
                                          b'blind_oracle_response',
                                          wally.AES_FLAG_DECRYPT)
    return status, bytes(aes_key)


def raw_exchange(payload, port=4443):
    """Send raw bytes, return everything the server answers until it closes."""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.sendall(payload)
        chunks = []
        try:
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except OSError:
            pass
    return b"".join(chunks)


def counter_bytes(n):
    return n.to_bytes(4, byteorder="little")


def wallet_id_of(pin_privkey):
    pin_pubkey = wally.ec_public_key_from_private_key(pin_privkey)
    return sha256(bytes(pin_pubkey)).hexdigest()[:8]


def pin_file_path():
    pins = [p for p in os.listdir("key_data/pins") if p.endswith(".pin")]
    assert len(pins) == 1, pins
    return "key_data/pins/" + pins[0]


def main():
    global SERVER_PUBKEY
    start_server()

    with open("key_data/server_keys/public.key", "rb") as f:
        SERVER_PUBKEY = bytearray(f.read())

    pin_privkey = bytearray(os.urandom(32))
    wally.ec_private_key_verify(pin_privkey)
    wallet = wallet_id_of(pin_privkey)
    pin_secret = os.urandom(32)
    wrong_secret = os.urandom(32)
    entropy = os.urandom(32)
    ctr = [0]

    def nxt():
        ctr[0] += 1
        return counter_bytes(ctr[0])

    # 0. fresh key_data: exactly one loud key-generation line, no pins notice
    assert count_matches(RE_NEWKEY) == 1, "key generation warning missing"
    assert count_matches(RE_PINS_MISSING) == 0, "pins notice on fresh install"
    print("PASS fresh install logs key generation warning once")

    # 0b. the public key is announced at start-up and key files are private
    assert event_groups(RE_PUBKEY) == [bytes(SERVER_PUBKEY).hex()], "public key line wrong"
    assert file_mode("key_data/server_keys/private.key") == 0o600, "private.key not 0600"
    print("PASS start-up announces the public key, private.key is 0600")

    # 1. set_pin -> event line with the wallet id
    st, key_a = make_request("set_pin", pin_privkey, pin_secret, nxt(), entropy)
    assert st == 200 and len(key_a) == 32, f"set_pin failed: {st}"
    stored = [RE_STORED.match(l) for l in server_log_lines() if RE_STORED.match(l)]
    assert len(stored) == 1 and stored[0].group(1) == wallet, "set_pin event line wrong"
    assert file_mode(pin_file_path()) == 0o600, "pin file not 0600"
    assert file_mode("key_data/pins") == 0o700, "pins directory not 0700"
    print("PASS set_pin (+ event line, pin file 0600)")

    # 2. set_pin replay (same counter): rejected, stored key untouched.
    # UPSTREAM PARITY: since Blockstream 608a23f set_pin persists the client's
    # replay counter, so the set_pin request itself cannot be replayed —
    # if this assertion ever fails, the protocol semantics changed.
    st, _ = make_request("set_pin", pin_privkey, pin_secret, counter_bytes(1), entropy)
    assert st == 400, f"set_pin replay semantics changed: {st}"
    assert event_groups(RE_REPLAY) == [wallet], "set_pin replay event line wrong"
    key_b = key_a
    print("PASS set_pin replay rejected (upstream parity, key untouched)")

    # 3. get_pin with correct pin -> latest stored key, correct event line
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k == key_b, f"correct get_pin: {st}, match={k == key_b}"
    correct = [RE_CORRECT.match(l) for l in server_log_lines() if RE_CORRECT.match(l)]
    assert len(correct) == 1 and correct[0].groups() == ("1", wallet), "correct-pin event line wrong"
    print("PASS get_pin correct -> key matches (+ event line)")

    # 4. replay (same counter) -> rejected (400), no key
    st, k = make_request("get_pin", pin_privkey, pin_secret, counter_bytes(ctr[0]))
    assert st == 400, f"replay not rejected: {st}"
    assert event_groups(RE_REPLAY) == [wallet] * 2, "replay event line wrong"
    print("PASS replay rejected (+ event line)")

    # 4b. a set_pin whose counter is not above the stored one is a replay too
    # (a captured old set_pin must never be able to re-randomize the key once
    # an unlock has advanced the counter); the stored key stays as it is -
    # the following steps keep unlocking with key_b
    for old_counter in (1, ctr[0]):
        st, _ = make_request("set_pin", pin_privkey, pin_secret, counter_bytes(old_counter), entropy)
        assert st == 400, f"set_pin replay (counter {old_counter}) not rejected: {st}"
    assert event_groups(RE_REPLAY) == [wallet] * 4, "set_pin replay event lines wrong"
    assert count_matches(RE_STORED) == 1, "replayed set_pin stored a new key"
    print("PASS set_pin with a stale counter is rejected, key untouched")

    # 5. wrong pin -> 200 but junk key; the FAILED attempt must also advance
    # the replay counter, so a correct pin with the same counter is rejected
    st, k = make_request("get_pin", pin_privkey, wrong_secret, nxt())
    assert st == 200 and k != key_b, "wrong pin returned real key!"
    st, k2 = make_request("get_pin", pin_privkey, pin_secret, counter_bytes(ctr[0]))
    assert st == 400, f"replay after wrong attempt not rejected: {st}"
    wrong = [RE_WRONG.match(l) for l in server_log_lines() if RE_WRONG.match(l)]
    assert len(wrong) == 1 and wrong[0].groups() == ("1", wallet), "wrong-pin event line wrong"
    print("PASS wrong pin -> junk key, replay counter advanced (+ event line)")

    # 6. correct pin resets wrong-attempt counter
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k == key_b, "correct pin after 1 wrong failed"
    print("PASS counter reset after correct pin")

    # 6b. two wrong attempts do NOT wipe (threshold is exactly three); junk keys differ
    st, j1 = make_request("get_pin", pin_privkey, wrong_secret, nxt())
    st2, j2 = make_request("get_pin", pin_privkey, wrong_secret, nxt())
    assert st == 200 and st2 == 200 and j1 != key_b and j2 != key_b and j1 != j2, "junk keys wrong"
    assert os.path.isfile(pin_file_path()), "pin file wiped after only two wrong attempts!"
    assert count_matches(RE_WIPE) == 0, "wipe line after two wrong attempts"
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k == key_b, "correct pin after 2 wrong failed"
    print("PASS two wrong attempts do not wipe, junk keys differ")

    # 7. restart server: static key + pin file must survive, no key regeneration
    stop_server()
    start_server()
    assert count_matches(RE_NEWKEY) == 1, "key regenerated on restart!"
    assert count_matches(RE_PINS_MISSING) == 0, "pins notice although pins exist"
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k == key_b, "persistence across restart broken"
    print("PASS restart persistence (no key regeneration)")

    # 8. corrupt pin file -> 400 (fail closed), restored file works again
    path = pin_file_path()
    with open(path, "rb") as f:
        original = f.read()
    corrupted = bytearray(original)
    corrupted[50] ^= 0xFF
    with open(path, "wb") as f:
        f.write(bytes(corrupted))
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 400, f"corrupt pin file not rejected: {st}"
    st, k = make_request("set_pin", pin_privkey, pin_secret, counter_bytes(ctr[0]), entropy)
    assert st == 400, f"set_pin with corrupt pin file not rejected: {st}"
    with open(path, "wb") as f:
        f.write(original)
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k == key_b, "restored pin file does not work"
    assert event_groups(RE_DAMAGED) == [wallet, wallet], "damaged-file event lines wrong"
    print("PASS corrupt pin file -> 400 (+ event lines), restore works")

    # 8b. a second wallet is isolated from the first one's failures
    pin_privkey_b = bytearray(os.urandom(32))
    wally.ec_private_key_verify(pin_privkey_b)
    secret_b = os.urandom(32)
    st, key_wb = make_request("set_pin", pin_privkey_b, secret_b, counter_bytes(1), os.urandom(32))
    assert st == 200

    # 9. three wrong attempts wipe the pin file (wallet A only)
    for _ in range(3):
        st, k = make_request("get_pin", pin_privkey, wrong_secret, nxt())
        assert st == 200 and k != key_b
    pins = os.listdir("key_data/pins")
    assert not any(p.startswith(wallet) for p in pins), f"pin file not wiped: {pins}"
    wipes = [RE_WIPE.match(l) for l in server_log_lines() if RE_WIPE.match(l)]
    assert len(wipes) == 1 and wipes[0].group(1) == wallet, "wipe event line wrong"
    attempts = [m.group(1) for m in (RE_WRONG.match(l) for l in server_log_lines()) if m]
    assert attempts == ["1", "1", "2", "1", "2", "3"], f"attempt sequence: {attempts}"
    print("PASS 3-strikes wipe (+ event line, attempt sequence)")

    # 9b. wallet B untouched by wallet A's wipe
    st, k = make_request("get_pin", pin_privkey_b, secret_b, counter_bytes(2))
    assert st == 200 and k == key_wb, "wallet B affected by wallet A wipe"
    print("PASS wallet isolation")

    # 10. correct pin after wipe -> junk key (file gone), not an error (blind semantics)
    st, k = make_request("get_pin", pin_privkey, pin_secret, nxt())
    assert st == 200 and k != key_b, "post-wipe get_pin leaked key or errored"
    assert event_groups(RE_UNKNOWN) == [wallet], "unknown-wallet event line wrong"
    print("PASS post-wipe correct pin -> junk key (+ event line)")

    # 10b. never-seen wallet -> 200 + junk (no existence oracle via status)
    never = bytearray(os.urandom(32))
    wally.ec_private_key_verify(never)
    st, k = make_request("get_pin", never, os.urandom(32), counter_bytes(1))
    assert st == 200 and len(k) == 32, f"unknown wallet: {st}"
    assert event_groups(RE_UNKNOWN) == [wallet, wallet_id_of(never)], "unknown-wallet event line wrong"
    print("PASS unknown wallet -> junk key (+ event line)")

    # 11. no .tmp leftovers from atomic writes
    leftovers = [p for p in os.listdir("key_data/pins") if p.endswith(".tmp")]
    assert not leftovers, f"tmp leftovers: {leftovers}"
    print("PASS no tmp leftovers")

    # 12. malformed requests -> 400, server keeps running
    st, _ = post("/get_pin", "{}")
    assert st == 400, f"missing data: {st}"
    st, _ = post("/get_pin", json.dumps({"data": "!!not-base64-length!!"}))
    assert st == 400, f"junk data: {st}"
    st, _ = post("/get_pin", json.dumps({"data": base64.b64encode(b"short").decode()}))
    assert st == 400, f"short data: {st}"
    st, _ = post("/get_pin", json.dumps({"data": 12345}))
    assert st == 400, f"non-string data: {st}"
    st, _ = post("/get_pin", json.dumps({"data": base64.b64encode(os.urandom(120)).decode()}))
    assert st == 400, f"well-formed garbage: {st}"
    print("PASS malformed requests -> 400")

    # 13. oversized body -> 400
    st, _ = post("/get_pin", json.dumps({"data": "A" * 20000}))
    assert st == 400, f"oversized body: {st}"
    print("PASS oversized body -> 400")

    # 13b. cross-origin POST refused; same-origin and origin-less pass
    st, _ = post("/get_pin", "{}", headers={"Origin": "https://evil.example"})
    assert st == 403, f"foreign origin not rejected: {st}"
    st, _ = post("/get_pin", "{}", headers={"Origin": "http://127.0.0.1:4443"})
    assert st == 400, f"same-origin request rejected: {st}"
    st, _ = post("/get_pin", "{}", headers={"Origin": "null"})
    assert st == 403, f"opaque origin not rejected: {st}"
    print("PASS origin check")

    # 13c. log injection: request-controlled text must never forge an event line
    before = tuple(count_matches(r) for r in ALL_EVENTS)
    st, _ = post("/get_pin", "{}", headers={"Origin": "https://Wrong pin (1. attempt) [wallet deadbeef]"})
    assert st == 403
    st, _ = post("/get_pin", "{}", headers={"Origin": "Too many wrong attempts [wallet deadbeef]"})
    assert st == 403
    with socket.create_connection(("127.0.0.1", 4443), timeout=5) as s:
        s.sendall(b"GET /Too many wrong attempts [wallet deadbeef] HTTP/1.0\r\n\r\n")
        s.recv(4096)
    with socket.create_connection(("127.0.0.1", 4443), timeout=5) as s:
        s.sendall(b"POST /get_pin HTTP/1.0\r\nOrigin: WARNING: NEW STATIC SERVER KEY GENERATED\r\nContent-Length: 2\r\n\r\n{}")
        s.recv(4096)
    for forged in ("Replay rejected [wallet deadbeef]", "Pin file damaged [wallet deadbeef]",
                   "Unknown wallet [wallet deadbeef]", "Pin limit reached [wallet deadbeef]",
                   "WARNING: PUBLIC KEY MISMATCH", "Static server public key: " + "ab" * 33):
        st, _ = post("/get_pin", "{}", headers={"Origin": forged})
        assert st == 403
        with socket.create_connection(("127.0.0.1", 4443), timeout=5) as s:
            s.sendall(b"GET /" + forged.encode() + b" HTTP/1.0\r\n\r\n")
            s.recv(4096)
    time.sleep(0.5)
    after = tuple(count_matches(r) for r in ALL_EVENTS)
    assert before == after, f"log injection forged an event line: {before} -> {after}"
    rejected = [l for l in server_log_lines() if l.startswith("Rejected cross-origin")]
    assert rejected and all("Wrong pin" not in l and "wrong attempts" not in l and "KEY GENERATED" not in l
                            for l in rejected), rejected
    print("PASS log injection cannot forge event lines")

    # 14. server still alive and correct afterwards (fresh wallet)
    pin_privkey2 = bytearray(os.urandom(32))
    wally.ec_private_key_verify(pin_privkey2)
    secret2 = os.urandom(32)
    st, key2 = make_request("set_pin", pin_privkey2, secret2, counter_bytes(1), os.urandom(32))
    assert st == 200
    st, k = make_request("get_pin", pin_privkey2, secret2, counter_bytes(2))
    assert st == 200 and k == key2
    print("PASS server healthy after abuse")

    # 15. GET routes
    for path, want in (("/", 200), ("/oracle_qr.html", 200), ("/qrcode.js", 200),
                       ("/html5-qrcode.min.js", 200), ("/jade-codec.js", 200), ("/app.js", 200),
                       ("/oracle_qr.js", 200), ("/apple-touch-icon.png", 200), ("/favicon.png", 200),
                       ("/nope", 404), ("/SimpleJadePinServer.py", 404), ("/key_data/server_keys/private.key", 404),
                       ("/../key_data/server_keys/private.key", 404)):
        got, _, _ = get(path)
        assert got == want, f"GET {path}: {got} != {want}"
    print("PASS GET routes (only the listed assets are served)")

    # 15b. the pages carry the server's key and contain no inline script, so
    # the strict Content-Security-Policy below can hold
    pubkey_hex = bytes(SERVER_PUBKEY).hex()
    for path, needle in (("/", pubkey_hex[:8] + "\u2026" + pubkey_hex[-4:]), ("/oracle_qr.html", pubkey_hex)):
        st, h, body = get(path)
        html = body.decode("utf-8")
        assert needle in html, f"{path}: server public key not injected"
        assert "{STATIC_SERVER" not in html, f"{path}: unreplaced placeholder"
        tags = re.findall(r"<script\b[^>]*>", html)
        assert tags and all(" src=" in t for t in tags), f"{path}: script tag without src"
        assert not re.search(r"<script\b[^>]*>\s*[^<\s]", html), f"{path}: inline script"
        assert not re.search(r"<[^>]*\son[a-z]+\s*=", html), f"{path}: inline event handler"
    print("PASS pages: key injected, no inline script or handlers")

    # 15c. security headers on pages, assets, errors and POST answers
    def check_security_headers(h, where):
        csp = h.get("content-security-policy", "")
        directives = {d.strip().split(" ")[0]: d.strip() for d in csp.split(";") if d.strip()}
        assert directives.get("default-src") == "default-src 'none'", f"{where}: default-src: {csp}"
        assert directives.get("script-src") == "script-src 'self'", f"{where}: script-src: {csp}"
        assert directives.get("frame-ancestors") == "frame-ancestors 'none'", f"{where}: frame-ancestors"
        assert directives.get("connect-src") == "connect-src 'self'", f"{where}: connect-src"
        assert h.get("x-content-type-options") == "nosniff", f"{where}: nosniff"
        assert h.get("x-frame-options") == "DENY", f"{where}: x-frame-options"
        assert h.get("referrer-policy") == "no-referrer", f"{where}: referrer-policy"
        assert h.get("server") == "SimpleJadePinServer", f"{where}: server header {h.get('server')}"

    for path in ("/", "/oracle_qr.html", "/app.js", "/favicon.png", "/nope"):
        _, h, _ = get(path)
        check_security_headers(h, "GET " + path)
    st, h, _ = post_with_headers("/get_pin", "{}")
    assert st == 400
    check_security_headers(h, "POST /get_pin")
    assert h.get("cache-control") == "no-store", "POST answer cacheable"
    print("PASS security headers")

    # 15d. assets are revalidated, not blindly cached: ETag + 304
    st, h, body = get("/app.js")
    etag = h.get("etag")
    assert st == 200 and etag and h.get("cache-control") == "no-cache", f"asset caching headers: {h}"
    st, h2, body2 = get("/app.js", headers={"If-None-Match": etag})
    assert st == 304 and body2 == b"", f"conditional GET: {st}"
    st, _, body3 = get("/app.js", headers={"If-None-Match": '"something-else"'})
    assert st == 200 and body3 == body, "stale validator must return the file"
    check_security_headers(h2, "304 answer")
    print("PASS asset revalidation (ETag / 304)")

    # 15e. answers the HTTP library produces on its own carry the headers too
    for raw, want in ((b"HEAD / HTTP/1.0\r\n\r\n", b" 501 "), (b"OPTIONS / HTTP/1.0\r\n\r\n", b" 501 "),
                      (b"GET /a b c HTTP/1.0\r\n\r\n", b" 400 "), (b"GET / HTTP/9.9\r\n\r\n", b" 505 ")):
        answer = raw_exchange(raw)
        head = answer.split(b"\r\n\r\n")[0].decode("latin-1")
        assert want in answer.split(b"\r\n")[0], f"{raw!r}: {answer[:40]!r}"
        hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in head.split("\r\n")[1:] if ":" in l}
        check_security_headers(hdrs, repr(raw))
    print("PASS library-generated error answers carry the security headers")

    # 16. existing key but pins directory removed -> loud notice at start-up
    stop_server()
    for p in os.listdir("key_data/pins"):
        os.remove("key_data/pins/" + p)
    os.rmdir("key_data/pins")
    start_server()
    assert count_matches(RE_PINS_MISSING) == 1, "pins-missing notice absent"
    assert count_matches(RE_NEWKEY) == 1, "key regenerated although private.key exists"
    print("PASS missing pins directory is reported at start-up")

    # 17. a private key readable by others is tightened and reported
    stop_server()
    os.chmod("key_data/server_keys/private.key", 0o644)
    start_server()
    assert count_matches(RE_PERMS) == 1, "permission notice absent"
    assert file_mode("key_data/server_keys/private.key") == 0o600, "private.key not tightened"
    print("PASS loose private.key permissions are tightened and reported")

    # 18. public.key that does not belong to private.key -> loud warning, file repaired
    stop_server()
    with open("key_data/server_keys/public.key", "wb") as f:
        f.write(b"\x02" + b"\x11" * 32)
    start_server()
    assert count_matches(RE_MISMATCH) == 1, "public key mismatch warning absent"
    with open("key_data/server_keys/public.key", "rb") as f:
        assert f.read() == bytes(SERVER_PUBKEY), "public.key not repaired"
    assert count_matches(RE_NEWKEY) == 1, "key regenerated"
    assert event_groups(RE_PUBKEY)[-1] == bytes(SERVER_PUBKEY).hex(), "server key changed"
    stop_server()
    start_server()
    assert count_matches(RE_MISMATCH) == 1, "mismatch warning repeated although keys match"
    print("PASS public/private key mismatch is reported once and repaired")

    # 19. an invalid private.key (empty, truncated) stops the server; it must
    # never be replaced by a freshly generated key
    stop_server()
    key_path = "key_data/server_keys/private.key"
    with open(key_path, "rb") as f:
        good_key = f.read()
    for bad in (b"", good_key[:31], b"\x00" * 32):
        with open(key_path, "wb") as f:
            f.write(bad)
        before_bad = count_matches(RE_BADKEY)
        code = run_server_expect_exit()
        assert code == 1, f"server did not refuse an invalid key (exit {code})"
        assert count_matches(RE_BADKEY) == before_bad + 1, "invalid-key error line absent"
        with open(key_path, "rb") as f:
            assert f.read() == bad, "invalid private.key was overwritten!"
    with open(key_path, "wb") as f:
        f.write(good_key)
    assert count_matches(RE_NEWKEY) == 1, "key regenerated"
    print("PASS invalid private.key stops the server and is left untouched")

    # 19b. unusable settings stop the server with one clear line, no traceback
    for env in ({"MAX_PIN_FILES": "many"}, {"MAX_PIN_FILES": "-1"}, {"REQUEST_TIMEOUT": "0"}):
        code = run_server_expect_exit(env=env)
        name = list(env)[0]
        assert code == 1, f"{env}: exit {code}"
        assert any(l.startswith("ERROR: " + name + " must be a whole number") for l in server_log_lines()), env
    with open("key_data/server.pem", "w") as f:
        f.write("this is not a certificate")
    code = run_server_expect_exit(args=("--port", str(TLS_PORT)))
    os.remove("key_data/server.pem")
    assert code == 1, f"broken certificate: exit {code}"
    assert any(l.startswith("ERROR: the TLS certificate") for l in server_log_lines()), "certificate error line absent"
    print("PASS unusable settings or certificate stop the server with a clear message")

    # 19c. key directory not accessible (only testable without root, which
    # ignores file permissions): clear error, and above all no claim that a
    # new key was generated
    if os.geteuid() != 0:
        before_new = count_matches(RE_NEWKEY)
        os.chmod("key_data/server_keys", 0o000)
        try:
            code = run_server_expect_exit()
        finally:
            os.chmod("key_data/server_keys", 0o700)
        assert code == 1, f"inaccessible key directory: exit {code}"
        assert any(l.startswith("ERROR: no permission to read or write") for l in server_log_lines()), "permission error line absent"
        assert count_matches(RE_NEWKEY) == before_new, "claimed a new key although nothing was written"
        with open(key_path, "rb") as f:
            assert f.read() == good_key, "private.key changed"
        print("PASS inaccessible key directory: clear error, no false key-generation warning")
    else:
        print("SKIP inaccessible key directory (running as root, which bypasses permissions)")

    # 20. pin file limit: new wallets are refused once it is reached, known
    # wallets keep working
    start_server(env={"MAX_PIN_FILES": "1"})
    wx = bytearray(os.urandom(32))
    wally.ec_private_key_verify(wx)
    wy = bytearray(os.urandom(32))
    wally.ec_private_key_verify(wy)
    sx = os.urandom(32)
    st, kx = make_request("set_pin", wx, sx, counter_bytes(1), os.urandom(32))
    assert st == 200, f"first wallet below the limit: {st}"
    st, _ = make_request("set_pin", wy, os.urandom(32), counter_bytes(1), os.urandom(32))
    assert st == 503, f"wallet above the limit not refused: {st}"
    assert event_groups(RE_LIMIT) == [wallet_id_of(wy)], "limit event line wrong"
    assert len(os.listdir("key_data/pins")) == 1, "pin file created above the limit"
    st, kx2 = make_request("set_pin", wx, sx, counter_bytes(2), os.urandom(32))
    assert st == 200, f"known wallet blocked by the limit: {st}"
    st, k = make_request("get_pin", wx, sx, counter_bytes(3))
    assert st == 200 and k == kx2, "known wallet cannot unlock at the limit"
    print("PASS pin file limit (new wallets refused, known wallets unaffected)")
    stop_server()

    # 20b. event lines stay whole under concurrent load, also with unbuffered
    # output (as in the Docker image): every one of them must still start a
    # line and end it, or a watcher anchored on the format would miss it
    start_server(env={"PYTHONUNBUFFERED": "1"})
    stored_before = count_matches(RE_STORED)
    flooding = True

    long_request = b"GET /" + b"A" * 60000 + b" x y z\r\n\r\n"
    lines_before = len(server_log_lines())

    def flood():
        # invalid requests, alternating with over-long request lines (the
        # HTTP library reports those with the request line in the message)
        while flooding:
            try:
                post("/get_pin", "{}", timeout=5)
            except Exception:
                pass
            try:
                raw_exchange(long_request)
            except Exception:
                pass

    threads = [threading.Thread(target=flood, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    try:
        for _ in range(60):
            fresh = bytearray(os.urandom(32))
            wally.ec_private_key_verify(fresh)
            for attempt in range(10):
                try:
                    st, _ = make_request("set_pin", fresh, os.urandom(32), counter_bytes(1), os.urandom(32))
                    break
                except urllib.error.URLError:
                    # connection not accepted under the flood: the request
                    # never reached the server, so it can simply be repeated
                    time.sleep(0.2)
            else:
                raise AssertionError("server unreachable under load")
            assert st == 200, f"set_pin under load: {st}"
    finally:
        flooding = False
        for t in threads:
            t.join(timeout=10)
    time.sleep(0.5)
    assert count_matches(RE_STORED) == stored_before + 60, \
        f"event lines damaged under load: {count_matches(RE_STORED) - stored_before} of 60 intact"
    assert not any("get_pin" in l and l != "get_pin" and not l.startswith(("127.0.0.1", "Request failed"))
                   for l in server_log_lines()), "log lines ran into each other"
    # the access lines are written through the same lock, cut to a fixed length
    during = server_log_lines()[lines_before:]
    assert any("AAAA" in l for l in during), "over-long requests did not reach the log"
    assert all(l.startswith("127.0.0.1 - - [") and l.endswith("...") for l in during if "AAAA" in l), \
        "over-long request text is not confined to its access line"
    assert max(len(l) for l in during) < 400, f"log line of {max(len(l) for l in during)} characters"
    print("PASS event lines stay intact under concurrent load (unbuffered output); access lines bounded")
    stop_server()

    # 21. TLS mode: a client that connects and stays silent must not block others
    with open("key_data/server.pem", "w") as f:
        f.write(TEST_TLS_PEM)
    start_server(args=("--port", str(TLS_PORT)), port=TLS_PORT, env={"REQUEST_TIMEOUT": "2"})
    tls_base = "https://127.0.0.1:" + str(TLS_PORT)
    insecure = ssl._create_unverified_context()
    st, h, _ = get("/", base=tls_base, context=insecure, timeout=5)
    assert st == 200, f"TLS GET: {st}"
    check_security_headers(h, "TLS GET /")
    silent = [socket.create_connection(("127.0.0.1", TLS_PORT), timeout=5) for _ in range(3)]
    time.sleep(0.5)
    try:
        started = time.time()
        st, _, _ = get("/", base=tls_base, context=insecure, timeout=5)
        assert st == 200, f"TLS GET with silent clients: {st}"
        assert time.time() - started < 3, "TLS request delayed by silent clients"
        st, _ = post("/get_pin", "{}", base=tls_base, context=insecure, timeout=5)
        assert st == 400, f"TLS POST with silent clients: {st}"
    except (OSError, urllib.error.URLError) as e:
        raise AssertionError(f"silent client blocked the TLS server: {e!r}")
    finally:
        for s in silent:
            s.close()
    # plain HTTP sent to the TLS port: one short log line, server keeps going
    with socket.create_connection(("127.0.0.1", TLS_PORT), timeout=5) as s:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        try:
            s.recv(4096)
        except OSError:
            pass
    time.sleep(0.5)
    st, _, _ = get("/", base=tls_base, context=insecure, timeout=5)
    assert st == 200, "TLS server unhealthy after a non-TLS client"
    # a client that never starts the handshake is dropped after the timeout
    # (REQUEST_TIMEOUT=2 here) instead of occupying a thread forever
    with socket.create_connection(("127.0.0.1", TLS_PORT), timeout=10) as s:
        started = time.time()
        try:
            closed = s.recv(1) == b""
        except OSError:
            closed = True
        waited = time.time() - started
    assert closed and 1 <= waited < 8, f"silent TLS client not dropped after the timeout (waited {waited:.1f}s)"
    time.sleep(0.3)
    lines = [l for l in server_log_lines() if l.startswith("Connection error")]
    assert "Connection error: TimeoutError" in lines, f"no timeout line: {set(lines)}"
    assert all(RE_CONN_ERROR.match(l) for l in lines), "connection error line carries more than the error type"
    stop_server()
    os.remove("key_data/server.pem")
    print("PASS TLS mode: silent and non-TLS clients do not block or break the server")

    # 22. nothing above may have produced a Python traceback in the log
    assert not any("Traceback" in l for l in server_log_lines()), "traceback in server log"
    print("PASS no traceback in the server log")

    print("ALL TESTS PASSED")
    print("--- server log ---")
    for line in server_log_lines():
        print(line)


if __name__ == "__main__":
    try:
        main()
    finally:
        if server_proc is not None and server_proc.poll() is None:
            server_proc.kill()
