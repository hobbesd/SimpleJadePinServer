# Changelog

All notable changes to this fork. The upstream project is
[Filiprogrammer/SimpleJadePinServer](https://github.com/Filiprogrammer/SimpleJadePinServer);
this changelog only covers the fork's modifications on top of it.

## 2026-11-19

### Server

- `set_pin` now stores the replay counter sent with the request instead of
  zero, following Blockstream's reference server (`608a23f`, "pindb: store
  the replay counter with each set_pin request"). A recorded `set_pin`
  request can no longer be replayed to re-randomize the stored key. The Jade
  only ever increments its counter, so its next unlock is unaffected;
  existing pin records keep working unchanged.

## 2026-11-16

### Web interface

- One-tap unlock: **Start scan** opens the rear camera directly (no separate
  permission and start buttons), and a scanned unlock request (`get_pin`) is
  sent automatically. A new-PIN request (`set_pin`) still needs the explicit
  **Generate reply QR** click. A **Switch camera** button appears on devices
  with more than one camera. The screen is kept awake during scan and reply
  where the browser supports it.
- A request is never sent twice. A request scanned again while the Jade
  still shows it is not posted a second time: the page waits for the answer
  that is on its way or shows the answer it already has. The time limit for
  an answer (20 s) covers the whole answer.
- Errors are shown instead of swallowed. Before, a rejected request (for
  example one that had already been used) left the page silent with a
  disabled button. Now the page explains a rejected request, an unreachable
  server (with retry), an origin mismatch, a full pin store and a camera that
  cannot be started, and says what to do next.
- A damaged scan or a QR code that is not a Jade PIN request no longer stops
  the scanner; it is reported and scanning continues.
- The BC-UR/CBOR/Bytewords code moved out of the two pages into one shared
  file, `jade-codec.js`; page logic lives in `app.js` and `oracle_qr.js`.
  The pages contain no inline script any more. The codec's output is
  unchanged (recorded vectors in `test_codec.js`), with two fixes for cases
  that were broken before: text and byte strings of 256 or more bytes are
  written with a correct length, and non-ASCII text is encoded as UTF-8.
- The Oracle QR page refuses a public key that is not 66 hex characters
  starting with `02` or `03`.

### Server

- TLS mode: the handshake now runs in the per-connection thread under the
  socket timeout. Before, one client that connected and sent nothing blocked
  all other clients for as long as it stayed connected.
- New event lines: `Replay rejected [wallet …]`, `Pin file damaged [wallet …]`,
  `Unknown wallet [wallet …]`, `Pin limit reached [wallet …]`. Before, the
  first two only showed as `Request failed: ValueError` and the third not at
  all. `Request failed:` lines now name the reason.
- Start-up: the server prints `Static server public key: …`; warns with
  `WARNING: PUBLIC KEY MISMATCH` when `public.key` does not belong to
  `private.key` (and only rewrites `public.key` when it is missing or wrong);
  reports and tightens a `private.key` that other users could read; and
  refuses to start with a `private.key` that is not a valid key instead of
  ever replacing it.
- Pin files are created with mode `0600`, the pins directory with `0700`.
- `MAX_PIN_FILES` (default 1000) caps the number of pin records; new wallets
  beyond the cap get HTTP 503, existing wallets are unaffected.
- Removing a pin file after the third wrong attempt is followed by a
  directory `fsync`, so the removal survives a crash.
- Responses carry a strict `Content-Security-Policy`, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy` and related headers; POST
  answers are `no-store`; assets are revalidated with `ETag`. The `Server`
  header no longer contains the Python version.
- Web assets are loaded once at start-up from the script's directory; a
  missing file stops the server immediately.
- Every log line is written with a single write under a lock. With
  unbuffered output (as in the Docker image) `print` emitted text and line
  break separately, so lines of concurrent requests could run into each
  other and an event line could be hidden from a watcher that anchors on
  the start of a line. The access lines of the HTTP library take the same
  path now (standard output instead of standard error, cut to a fixed
  length, printable ASCII only); before, an over-long request line could
  be written across an event line where both streams end up in one place.
- `REQUEST_TIMEOUT` (default 30 s) sets how long a connection may stay
  silent; unusable values for it or for `MAX_PIN_FILES`, and a TLS
  certificate that cannot be loaded, stop the server with a clear message.
  Start-up messages are only logged once the action they report succeeded.

### Docker

- Base image pinned by digest. Compose runs the container with a read-only
  root filesystem, all capabilities dropped, `no-new-privileges`, process
  and memory limits and a bounded container log (this sets the `json-file`
  log driver for the container; remove the `logging` block if your host
  collects container logs through another driver). Because of the dropped
  capabilities `key_data/` must belong to root (it does when Docker created
  it). A `.dockerignore` keeps `key_data/` out of the build context.

### Dependencies

- `wallycore` 1.5.6 → 1.6.1 (1.6.0 is a security release with stricter input
  validation; 1.6.1 extends the careful copying of secret data). Every
  primitive this server uses was compared between both versions with fixed
  inputs and produced identical output, including the error behaviour the
  server relies on. All official PyPI artifact hashes are pinned.

### Tests

- `test_protocol.py`: 37 checks (was 22) — new event lines, `set_pin` with
  a stale counter, file modes, start-up checks, pin limit, intact event
  lines under concurrent load, security headers on every kind of answer,
  asset revalidation, TLS mode with silent and non-TLS clients (including
  the handshake timeout), no traceback in the log.
- New `test_codec.js` (Node.js): official Bytewords/UR vectors, an
  independent Jade-side encoder, damaged-scan rejection, recorded output
  vectors.
- New `test_browser.js` (optional, Playwright): the whole flow in a real
  browser with a simulated Jade and a fake camera, against a real server
  instance with throwaway keys.

## 2026-09-02

### Security / logging

- Security-relevant events are logged as fixed-format lines that always start
  a log line and carry a short, non-secret wallet id (first 8 hex characters
  of the pin file name): `New pin stored [wallet …]`,
  `Correct pin on the N. attempt [wallet …]`, `Wrong pin (N. attempt) [wallet …]`,
  `Too many wrong attempts [wallet …]`. External log watchers can anchor on
  these lines; see *Security notes* in the README.
- The value of a rejected `Origin` header is sanitised before it is logged, so
  request-controlled text can no longer forge an event line.
- Loud start-up warnings: `WARNING: NEW STATIC SERVER KEY GENERATED` when no
  private key exists (on an existing installation this means `key_data` is
  missing or not mounted), and `NOTICE: pins directory missing` when a key
  exists but the pin directory does not (in that state `get_pin` answers with
  junk keys and the Jade counts the attempts as failures).

### Dependencies

- `wallycore` 1.5.3 → 1.5.6. The release replaces libc `memcpy` for secret
  data with a byte-wise copy to avoid leaving key material in SSE/AVX
  registers, and hides internal symbols. Every primitive used by this server
  was compared between both versions with fixed inputs and produced identical
  output. All official PyPI artifact hashes of the release are pinned.

### Tests

- The end-to-end suite grew from 16 to 22 checks: exact event-line format
  (the alert contract), log-injection resistance via `Origin` header and
  request line, key-generation warning exactly once and never on restart,
  pins-directory notice, two wrong attempts do not wipe, wallet isolation,
  never-seen wallet answers with a junk key, well-formed garbage is rejected.

### Documentation

- README: event lines and their guarantees documented; supply-chain wording
  updated (the dependency pin covers every official artifact and only changes
  deliberately).

## 2026-08-22 — initial hardened fork

### Server

- Security checks raise explicit errors instead of `assert` (safe under
  `python -O`); a failed check yields HTTP 400 and never key material.
- Constant-time comparison for the PIN hash and the pin-file HMAC.
- Atomic pin-file and first-time key writes (temp file, `fsync`, rename,
  directory `fsync`); the private key is created with mode `0600`.
- Threaded server with a per-connection read timeout, a request body cap,
  and a lock that serialises all PIN state operations; responses carry
  `Content-Length` and are sent after the lock is released.
- Same-origin check on `POST` (`Origin` must match `Host` or an entry of
  `ALLOWED_ORIGINS`); non-browser clients without `Origin` are unaffected.
- Unbuffered stdout in the Docker image so log lines appear immediately.

### Web interface

- Mobile-friendly card layout, constrained camera view, fragment progress,
  reload button, favicon and touch icon.
- BC-UR decoder verifies the per-fragment bytewords CRC32 and the reassembled
  message CRC32; a mis-scan is reported instead of producing a corrupt
  request. Fixed 32/64-bit reads in the CBOR decoder, fragment reset when the
  fragment count changes, double-submit guard, `textContent` for scanned data,
  `JSON.stringify` for request bodies.

### Supply chain

- `html5-qrcode` vendored (sha512-verified against the original SRI hash),
  `wallycore` pinned with `--require-hashes`, no CDN access at runtime.
- Docker Compose binds the container port to loopback only.

### Tests and licensing

- End-to-end protocol test suite (client simulator with the same wally
  primitives), including upstream-parity checks for `set_pin` semantics.
- MIT `LICENSE` with third-party notices (`LICENSES/`), README rewrite with
  screenshots, security notes and disclaimer.
