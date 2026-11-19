#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from hashlib import sha256
import argparse
import base64
import hmac
import os
import re
import stat
import threading
import wallycore as wally
import urllib.parse
import signal
import ssl
import sys
import json

# Key material and pin files live below the working directory (unchanged from
# upstream); the web assets are loaded from the directory of this script.
tls_cert_path = "key_data/server.pem"
server_keys_path = "key_data/server_keys"
pins_path = "key_data/pins"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Real requests are well under 1 KB; anything bigger is not a Jade PIN request
MAX_CONTENT_LENGTH = 8192

# Upper bound for the number of stored pin files (environment variable
# MAX_PIN_FILES, read at start-up). Every set_pin of a new wallet creates one
# small file; without a ceiling any client that can reach the server could
# fill the disk. Existing wallets are never affected.
MAX_PIN_FILES = 1000

# Serializes all PIN state operations (threads only exist to survive slow/stalled clients)
state_lock = threading.Lock()

log_lock = threading.Lock()

# Longest request text kept in an access log line
ACCESS_LOG_MAX = 200

def log(line):
    # Every log line is written with a single write call, under a lock.
    # print() may emit the text and the line break separately, and lines of
    # concurrent requests could then run into each other - a watcher that
    # anchors on the start of a line would miss the event.
    with log_lock:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()

def env_int(name, default, minimum):
    # Integer setting from the environment; a value that is not usable stops
    # the server with a clear message instead of a traceback.
    raw = os.environ.get(name)

    if raw is None or raw.strip() == "":
        return default

    try:
        value = int(raw)

        if value < minimum:
            raise ValueError
    except ValueError:
        log("ERROR: " + name + " must be a whole number of at least " + str(minimum) + ".")
        sys.exit(1)

    return value

BAD_REQUEST_HTML = b"<html><head><title>Bad request</title></head><body>Bad request</body></html>"
NOT_FOUND_HTML = b"<html><head><title>Not found</title></head><body>Not found</body></html>"

# Sent with every response. The pages only load their own scripts (no inline
# script, no eval), talk only to this server and may not be framed.
SECURITY_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(self), microphone=(), geolocation=()"),
    ("Content-Security-Policy",
     "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
     "img-src 'self' data:; connect-src 'self'; media-src 'self' blob:; "
     "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
)

# URL path -> (file name next to this script, content type)
STATIC_FILES = {
    "/qrcode.js": ("qrcode.js", "text/javascript"),
    "/html5-qrcode.min.js": ("html5-qrcode.min.js", "text/javascript"),
    "/jade-codec.js": ("jade-codec.js", "text/javascript"),
    "/app.js": ("app.js", "text/javascript"),
    "/oracle_qr.js": ("oracle_qr.js", "text/javascript"),
    "/apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "/favicon.png": ("favicon.png", "image/png"),
    "/": ("index.html", "text/html; charset=utf-8"),
    "/oracle_qr.html": ("oracle_qr.html", "text/html; charset=utf-8"),
}

# URL path -> (content type, body, etag); filled once at start-up
ASSETS = {}

class RequestError(Exception):
    # A request the server refuses. `reason` is always one of the fixed
    # strings in this file, never request-controlled text, so it is safe to log.
    def __init__(self, reason, status=400):
        super().__init__(reason)
        self.reason = reason
        self.status = status

class PinFileError(Exception):
    # The stored pin file exists but cannot be trusted (wrong size, unknown
    # version, failed integrity check).
    pass

def origin_allowed(origin, host):
    # Cross-site hardening: browsers include an Origin header on cross-site
    # POSTs. Same-origin requests carry our own authority (== Host header),
    # non-browser clients (curl, Green, monitoring) send no Origin at all.
    # Anything else is refused. ALLOWED_ORIGINS may list extra permitted
    # origins (comma-separated) for deployments behind additional hostnames.
    if origin is None:
        return True

    try:
        netloc = urllib.parse.urlparse(origin).netloc
    except ValueError:
        return False

    if not netloc:
        return False

    allowed = {host.lower()}

    for entry in os.environ.get("ALLOWED_ORIGINS", "").split(","):
        entry = entry.strip()

        if not entry:
            continue

        if "://" in entry:
            entry = urllib.parse.urlparse(entry).netloc

        allowed.add(entry.lower())

    return netloc.lower() in allowed

def safe_log_token(value, max_len=64):
    # Log hygiene: request-controlled strings (e.g. the Origin header) are
    # reduced to a conservative character set before they reach the log, so
    # they can never forge the server's own event lines that external tooling
    # (such as an alert watcher grepping the container log) matches on.
    if value is None:
        return "-"

    cleaned = re.sub(r"[^A-Za-z0-9.:_/-]", "?", str(value))[:max_len]

    return cleaned or "-"

class GracefulExitHandler:
    def __init__(self, server):
        self.server = server
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)

    def graceful_shutdown(self, signum, frame):
        self.server.server_close()
        log("Server stopped")
        sys.exit(0)

class PinHTTPServer(ThreadingHTTPServer):
    # Pending connections the kernel may queue while all are being accepted
    # (the library default of 5 turns a short burst into refused connections)
    request_queue_size = 64

    def handle_error(self, request, client_address):
        # A connection that fails before or outside request handling (failed
        # or timed-out TLS handshake, reset by peer). One short line instead
        # of a traceback; the exception text is not logged because parts of
        # it can be influenced by the peer.
        log("Connection error: " + type(sys.exc_info()[1]).__name__)

class MyServer(BaseHTTPRequestHandler):
    # Read timeout so a stalled client cannot hold a worker thread forever
    timeout = 30

    # http.server answers a request line it cannot parse in HTTP/0.9 style:
    # a bare error page without status line or headers. Treat such requests
    # as HTTP/1.0 so that these answers carry the security headers as well.
    default_request_version = "HTTP/1.0"

    def version_string(self):
        # Server header: do not advertise the Python version
        return "SimpleJadePinServer"

    def log_message(self, format, *args):
        # The access and error lines of the HTTP library go through log() as
        # well. Left on stderr they would be written outside the lock and at
        # any length (they contain the request line), and where both streams
        # end up in one place an event line could land in the middle of one.
        # The line starts with the client address, so request-controlled text
        # can never begin a line; it is cut to a fixed length and reduced to
        # printable ASCII.
        text = "".join(ch if " " <= ch <= "~" else "\\x%02x" % (ord(ch) & 0xff) for ch in format % args)

        if len(text) > ACCESS_LOG_MAX:
            text = text[:ACCESS_LOG_MAX] + "..."

        log("%s - - [%s] %s" % (self.address_string(), self.log_date_time_string(), text))

    def setup(self):
        # The TLS handshake runs here, in the per-connection thread and under
        # the read timeout. Done in accept() instead (the default), a single
        # client that connects and then stays silent would block the listener
        # and with it every other client.
        if isinstance(self.request, ssl.SSLSocket):
            self.request.settimeout(self.timeout)
            self.request.do_handshake()

        super().setup()

    def send_bad_request(self):
        self.send_full_response(400, "text/html", BAD_REQUEST_HTML)

    def end_headers(self):
        # Every response gets the security headers - also 304 answers and the
        # error pages http.server produces on its own (bad request line,
        # unsupported method)
        for name, value in SECURITY_HEADERS:
            self.send_header(name, value)

        super().end_headers()

    def send_full_response(self, status, content_type, body, extra_headers=()):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.send_header("Content-length", str(len(body)))

        for name, value in extra_headers:
            self.send_header(name, value)

        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # Fail closed on any malformed or invalid request: no key material, just an error status.
        # process_post never writes to the socket, so an error here can never
        # produce a half-sent response.
        try:
            status, content_type, body = self.process_post()
        except RequestError as e:
            log("Request failed: " + e.reason)
            status, content_type, body = e.status, "text/html", BAD_REQUEST_HTML
        except Exception as e:
            log("Request failed: " + type(e).__name__)
            status, content_type, body = 400, "text/html", BAD_REQUEST_HTML

        try:
            # Answers are bound to one request and must never be served from a cache
            self.send_full_response(status, content_type, body, (("Cache-Control", "no-store"),))
        except Exception:
            pass  # client already disconnected

    def process_post(self):
        origin = self.headers.get('Origin')

        if not origin_allowed(origin, self.headers.get('Host', '')):
            log("Rejected cross-origin request from origin " + safe_log_token(origin))
            return 403, "text/plain", b"Forbidden"

        content_len = int(self.headers.get('Content-length', '0'))

        if content_len < 0 or content_len > MAX_CONTENT_LENGTH:
            raise RequestError("invalid content length")

        post_body = self.rfile.read(content_len)
        try:
            params = json.loads(post_body)
        except json.JSONDecodeError:
            params = {}

        request = urllib.parse.urlparse(self.path)

        if request.path == "/set_pin":
            log("set_pin")

            if not 'data' in params:
                return 400, "text/html", BAD_REQUEST_HTML

            data = base64.b64decode(params['data'])

            if len(data) <= 37:
                raise RequestError("request data too short")
            cke = data[:33]
            replay_counter = data[33:37]
            encrypted_data = data[37:]

            with state_lock:
                private_key, public_key = generate_ec_key_pair(replay_counter, cke)

                payload = wally.aes_cbc_with_ecdh_key(private_key, None, encrypted_data, cke, b'blind_oracle_request', wally.AES_FLAG_DECRYPT)

                # set_pin requires client-passed entropy
                if len(payload) != 32 + 32 + 65:
                    raise RequestError("invalid payload length")
                pin_secret = payload[:32]
                entropy = payload[32:64]
                sig = payload[64:]
                signed_msg = bytearray(sha256(cke + replay_counter + pin_secret + entropy).digest())
                pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

                pin_pubkey_hash = sha256(pin_pubkey).digest()

                try:
                    _, _, _, replay_local = load_pin_fields(pin_pubkey_hash, pin_pubkey)
                except FileNotFoundError:
                    # A wallet this server has not seen before
                    if count_pin_files() >= MAX_PIN_FILES:
                        log("Pin limit reached [wallet " + wallet_id(pin_pubkey_hash) + "]")
                        raise RequestError("pin limit reached", 503)
                except PinFileError:
                    log("Pin file damaged [wallet " + wallet_id(pin_pubkey_hash) + "]")
                    raise RequestError("pin file damaged")
                else:
                    # Enforce anti replay (client counter must be greater than the server counter)
                    check_replay_counter(replay_counter, replay_local, pin_pubkey_hash)

                our_random = os.urandom(32)
                new_key = wally.hmac_sha256(our_random, entropy)

                hash_pin_secret = sha256(pin_secret).digest()
                # Persist the client's replay counter (as Blockstream does since
                # 608a23f), so the set_pin request itself cannot be replayed
                save_pin_fields(pin_pubkey_hash, hash_pin_secret, new_key, pin_pubkey, 0, replay_counter)
                log("New pin stored [wallet " + wallet_id(pin_pubkey_hash) + "]")
                aes_key = wally.hmac_sha256(new_key, pin_secret)

                iv = os.urandom(16)
                encrypted_key = wally.aes_cbc_with_ecdh_key(private_key, iv, aes_key, cke, b'blind_oracle_response', wally.AES_FLAG_ENCRYPT)

            return 200, "application/json", b'{"data":"' + base64.b64encode(encrypted_key) + b'"}'
        elif request.path == "/get_pin":
            log("get_pin")

            if not 'data' in params:
                return 400, "text/html", BAD_REQUEST_HTML

            data = base64.b64decode(params['data'])

            if len(data) <= 37:
                raise RequestError("request data too short")
            cke = data[:33]
            replay_counter = data[33:37]
            encrypted_data = data[37:]

            with state_lock:
                private_key, public_key = generate_ec_key_pair(replay_counter, cke)

                payload = wally.aes_cbc_with_ecdh_key(private_key, None, encrypted_data, cke, b'blind_oracle_request', wally.AES_FLAG_DECRYPT)

                # get_pin does not need client-passed entropy
                if len(payload) != 32 + 65:
                    raise RequestError("invalid payload length")
                pin_secret = payload[:32]
                sig = payload[32:]
                signed_msg = bytearray(sha256(cke + replay_counter + pin_secret).digest())
                pin_pubkey = wally.ec_sig_to_public_key(signed_msg, sig)

                pin_pubkey_hash = sha256(pin_pubkey).digest()

                try:
                    saved_hash_pin_secret, saved_key, counter, replay_local = load_pin_fields(pin_pubkey_hash, pin_pubkey)
                except FileNotFoundError:
                    # Return a random incorrect key to the Jade
                    log("Unknown wallet [wallet " + wallet_id(pin_pubkey_hash) + "]")
                    saved_key = os.urandom(32)
                except PinFileError:
                    log("Pin file damaged [wallet " + wallet_id(pin_pubkey_hash) + "]")
                    raise RequestError("pin file damaged")
                else:
                    # Enforce anti replay (client counter must be greater than the server counter)
                    check_replay_counter(replay_counter, replay_local, pin_pubkey_hash)

                    hash_pin_secret = sha256(pin_secret).digest()

                    if hmac.compare_digest(hash_pin_secret, saved_hash_pin_secret):
                        log("Correct pin on the " + str(counter + 1) + ". attempt [wallet " + wallet_id(pin_pubkey_hash) + "]")
                        save_pin_fields(pin_pubkey_hash, hash_pin_secret, saved_key, pin_pubkey, 0, replay_counter)
                    else:
                        log("Wrong pin (" + str(counter + 1) + ". attempt) [wallet " + wallet_id(pin_pubkey_hash) + "]")

                        if counter >= 2:
                            os.remove(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin")
                            # Make the removal durable: after a crash the file
                            # must not come back with one attempt left
                            fsync_dir(pins_path)
                            log("Too many wrong attempts [wallet " + wallet_id(pin_pubkey_hash) + "]")
                        else:
                            save_pin_fields(pin_pubkey_hash, saved_hash_pin_secret, saved_key, pin_pubkey, counter + 1, replay_counter)

                        # Return a random incorrect key to the Jade
                        saved_key = os.urandom(32)

                aes_key = wally.hmac_sha256(saved_key, pin_secret)

                iv = os.urandom(16)
                encrypted_key = wally.aes_cbc_with_ecdh_key(private_key, iv, aes_key, cke, b'blind_oracle_response', wally.AES_FLAG_ENCRYPT)

            return 200, "application/json", b'{"data":"' + base64.b64encode(encrypted_key) + b'"}'
        else:
            return 404, "text/html", NOT_FOUND_HTML

    def do_GET(self):
        try:
            self.handle_get()
        except Exception as e:
            log("Request failed: " + type(e).__name__)
            try:
                self.send_bad_request()
            except Exception:
                pass  # client already disconnected

    def handle_get(self):
        request = urllib.parse.urlparse(self.path)
        asset = ASSETS.get(request.path)

        if asset is None:
            self.send_full_response(404, "text/html", NOT_FOUND_HTML)
            return

        content_type, body, etag = asset
        # no-cache = "revalidate before use": a browser keeps the files but
        # asks on every load whether they changed, so an updated server is
        # never mixed with stale scripts.
        cache_headers = (("ETag", etag), ("Cache-Control", "no-cache"))

        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)

            for name, value in cache_headers:
                self.send_header(name, value)

            self.end_headers()
            return

        self.send_full_response(200, content_type, body, cache_headers)

def load_assets():
    # Read every web asset once at start-up. A missing file stops the server
    # right away instead of failing later on the first request.
    pubkey_hex = bytes2hex(STATIC_SERVER_PUBLIC_KEY)
    placeholders = {
        b"{STATIC_SERVER_PUBLIC_KEY_SHORT}": (pubkey_hex[:8] + "…" + pubkey_hex[-4:]).encode("utf-8"),
        b"{STATIC_SERVER_PUBLIC_KEY}": pubkey_hex.encode("utf-8"),
    }

    for url_path, (file_name, content_type) in STATIC_FILES.items():
        with open(os.path.join(BASE_DIR, file_name), "rb") as f:
            body = f.read()

        if content_type.startswith("text/html"):
            for placeholder, value in placeholders.items():
                body = body.replace(placeholder, value)

        etag = '"' + sha256(body).hexdigest()[:32] + '"'
        ASSETS[url_path] = (content_type, body, etag)

def fsync_dir(path):
    dir_fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)

def write_file_atomic(path, data):
    # Temp file, fsync, rename, directory fsync: a crash at any point leaves
    # either the old or the new file, never a partial one. The file is only
    # ever readable by its owner.
    tmp_path = path + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)

    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, path)
    fsync_dir(os.path.dirname(path))

def count_pin_files():
    try:
        return sum(1 for entry in os.scandir(pins_path) if entry.name.endswith(".pin"))
    except FileNotFoundError:
        return 0

def check_replay_counter(replay_counter, replay_local, pin_pubkey_hash):
    client_counter = int.from_bytes(replay_counter, byteorder='little', signed=False)
    server_counter = int.from_bytes(replay_local, byteorder='little', signed=False)

    if client_counter <= server_counter:
        log("Replay rejected [wallet " + wallet_id(pin_pubkey_hash) + "]")
        raise RequestError("replay counter not increasing")

def save_pin_fields(pin_pubkey_hash, hash_pin_secret, aes_key, pin_pubkey, counter, replay_counter):
    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    count_bytes = counter.to_bytes(1, byteorder='little')
    plaintext = hash_pin_secret + aes_key + count_bytes + replay_counter
    iv = os.urandom(16)
    encrypted = iv + wally.aes_cbc(storage_aes_key, iv, plaintext, wally.AES_FLAG_ENCRYPT)
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    version_bytes = b'\x01'
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)

    os.makedirs(pins_path, mode=0o700, exist_ok=True)

    # Atomic write: this file is rewritten on every unlock (replay counter update);
    # a crash mid-write must never corrupt the existing pin file
    pin_file_path = pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin"
    write_file_atomic(pin_file_path, version_bytes + hmac_payload + encrypted)

def load_pin_fields(pin_pubkey_hash, pin_pubkey):
    with open(pins_path + "/" + bytes2hex(pin_pubkey_hash) + ".pin", "rb") as f:
        data = f.read()

    if len(data) != 129:
        raise PinFileError("corrupt pin file")

    version_bytes = data[:1]

    if version_bytes[0] != 1:
        raise PinFileError("unsupported pin file version")

    hmac_received = data[1:33]
    encrypted = data[33:]
    pin_auth_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey_hash)
    hmac_payload = wally.hmac_sha256(pin_auth_key, version_bytes + encrypted)

    if not hmac.compare_digest(hmac_payload, hmac_received):
        raise PinFileError("pin file hmac mismatch")

    storage_aes_key = wally.hmac_sha256(STATIC_SERVER_AES_PIN_DATA, pin_pubkey)
    iv = encrypted[:16]

    try:
        plaintext = wally.aes_cbc(storage_aes_key, iv, encrypted[16:], wally.AES_FLAG_DECRYPT)
    except ValueError:
        raise PinFileError("corrupt pin file")

    if len(plaintext) != 32 + 32 + 1 + 4:
        raise PinFileError("corrupt pin file")

    saved_hash_pin_secret = plaintext[:32]
    saved_key = plaintext[32:64]
    counter = plaintext[64]
    replay_counter_persisted = plaintext[65:69]

    return saved_hash_pin_secret, saved_key, counter, replay_counter_persisted

def bytes2hex(byte_array):
    return ''.join('{:02x}'.format(x) for x in byte_array)

def wallet_id(pin_pubkey_hash):
    # Short, non-secret identifier for log lines (prefix of the pin file name)
    return bytes2hex(pin_pubkey_hash)[:8]

def generate_ec_key_pair(replay_counter, cke):
    tweak = sha256(wally.hmac_sha256(cke, replay_counter)).digest()
    private_key = wally.ec_private_key_bip341_tweak(STATIC_SERVER_PRIVATE_KEY, tweak, 0)
    wally.ec_private_key_verify(private_key)
    public_key = wally.ec_public_key_from_private_key(private_key)

    return private_key, public_key

def generate_private_key():
    while True:
        private_key = bytearray(os.urandom(32))
        try:
            wally.ec_private_key_verify(private_key)
            break
        except Exception:
            pass

    return private_key

def get_static_server_key_pair():
    os.makedirs(server_keys_path, exist_ok=True)
    private_key_path = server_keys_path + "/private.key"
    public_key_path = server_keys_path + "/public.key"

    if os.path.isfile(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = bytearray(f.read())

        # Refuse to run with a key file that is not a valid key (for example
        # an empty file). Generating a replacement here would silently break
        # every paired Jade.
        try:
            if len(private_key) != 32:
                raise ValueError("wrong length")

            wally.ec_private_key_verify(private_key)
        except ValueError:
            log("ERROR: " + private_key_path + " is not a valid private key. "
                  "Restore it from your backup; the server will not start without it.")
            sys.exit(1)

        mode = stat.S_IMODE(os.stat(private_key_path).st_mode)

        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            os.chmod(private_key_path, 0o600)
            log("NOTICE: private.key was accessible to other users (mode "
                  + format(mode, "04o") + "), tightened to 0600")
    else:
        private_key = generate_private_key()

        # Atomic first-time write: a crash here must never leave a partial key
        # file behind (loss of this key means seed-restore only)
        write_file_atomic(private_key_path, private_key)

        # Loud on purpose: on an existing installation this means key_data is
        # missing or not mounted. The Jade cannot be unlocked with a new key.
        # Logged only once the key really is on disk.
        log("WARNING: NEW STATIC SERVER KEY GENERATED - no private.key found in "
              + server_keys_path + ". Expected on a fresh install only; otherwise "
              "key_data is missing or not mounted!")

    public_key = wally.ec_public_key_from_private_key(private_key)

    # public.key is derived data, kept for convenience (USB/BLE setup reads
    # it). It is only written when missing or wrong; a mismatch is reported
    # because it means the private key on disk is not the one this
    # installation used before.
    stored_public_key = None

    if os.path.isfile(public_key_path):
        with open(public_key_path, "rb") as f:
            stored_public_key = f.read()

    if stored_public_key != bytes(public_key):
        with open(public_key_path, "wb") as f:
            f.write(public_key)

        if stored_public_key is not None:
            log("WARNING: PUBLIC KEY MISMATCH - public.key did not belong to private.key. "
                  "If the private key was replaced or restored from a different backup, "
                  "a paired Jade cannot be unlocked with it. public.key was rewritten.")

    return private_key, public_key

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Simple reimplementation of the blind_pin_server for the Blockstream Jade, "
                    "along with a basic web interface"
    )
    parser.add_argument(
        "-p", "--port",
        type=int, default=4443,
        help="port number to listen on"
    )
    parser.add_argument(
        "--tls",
        action=argparse.BooleanOptionalAction, default=True,
        help="whether to use HTTPS (HTTP over TLS) for secure access, required by modern browsers "
             "to enable webcam access on non-localhost connections. "
             "Enabled by default; use --no-tls to disable."
    )
    args = parser.parse_args()

    # Event lines must reach the log the moment they happen, also when stdout
    # is a pipe or a file (log watchers depend on it), not when a buffer fills
    sys.stdout.reconfigure(line_buffering=True)

    MAX_PIN_FILES = env_int("MAX_PIN_FILES", 1000, 0)
    # Seconds a connection may stay silent (also covers the TLS handshake)
    MyServer.timeout = env_int("REQUEST_TIMEOUT", 30, 1)

    listen_ip = "0.0.0.0"
    server = PinHTTPServer((listen_ip, args.port), MyServer)

    if args.tls:
        if not os.path.isfile(tls_cert_path):
            log(
                f"TLS certificate not found at {tls_cert_path}. "
                "Either provide a certificate or use --no-tls to disable TLS. "
                "Note that TLS is required by modern browsers to enable webcam access on "
                "non-localhost connections."
            )
            sys.exit(1)

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        try:
            ssl_context.load_cert_chain(certfile=tls_cert_path)
        except (ssl.SSLError, OSError) as e:
            log(f"ERROR: the TLS certificate at {tls_cert_path} could not be loaded ({type(e).__name__}). "
                "The file must be readable and contain the private key and the certificate in PEM format.")
            sys.exit(1)
        # Handshake is deferred to the per-connection thread, see MyServer.setup
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True,
                                                do_handshake_on_connect=False)

    log(f"Server starting on {'https' if args.tls else 'http'}://{listen_ip}:{args.port}")

    key_existed = os.path.isfile(server_keys_path + "/private.key")
    try:
        STATIC_SERVER_PRIVATE_KEY, STATIC_SERVER_PUBLIC_KEY = get_static_server_key_pair()
    except PermissionError:
        log("ERROR: no permission to read or write " + server_keys_path + ". key_data must belong to "
              "the user this server runs as (root in the Docker Compose setup of this repository, "
              "which runs without the capability to bypass file permissions).")
        sys.exit(1)
    STATIC_SERVER_AES_PIN_DATA = wally.hmac_sha256(STATIC_SERVER_PRIVATE_KEY, b'pin_data')
    log("Static server public key: " + bytes2hex(STATIC_SERVER_PUBLIC_KEY))

    if key_existed and not os.path.isdir(pins_path):
        # An existing key without any pin directory: fine before the very first
        # set_pin, alarming afterwards (get_pin would answer with junk keys and
        # the Jade would count those as failed attempts).
        log("NOTICE: pins directory missing (" + pins_path + ") - expected only "
              "before the first set_pin; otherwise pin data was lost!")

    load_assets()

    GracefulExitHandler(server)
    server.serve_forever()
