#!/usr/bin/env node
// Browser end-to-end test of the web interface (optional; needs Playwright).
//
// A simulated Jade shows its PIN request as QR codes to the page through a
// fake camera (Chromium plays a generated video as camera input). The page
// scans it, talks to a real server instance started by this test (throwaway
// key_data in a temp directory), and shows the reply QR codes, which the
// simulated Jade decrypts. Covered: one-tap unlock, an already used request,
// an unreachable server and a proxy error with retry, a damaged scan, a scan
// stopped by hand, a new scan while an answer is still pending, switching
// cameras, new-PIN confirmation, a single-QR request, the Oracle QR page,
// and (other engines) the page without a camera. Any Content-Security-Policy
// violation fails the test. The one-tap unlock runs with the JavaScript QR
// decoder (as on browsers without a native detector, e.g. Safari) and small
// QR codes like the Jade's low density setting; the other camera scenarios
// use Chromium's native detector, which copes better with the generated
// low-resolution test video.
//
//     PYTHON=venv/bin/python node test_browser.js [chromium|webkit|firefox]
//
// Environment: PYTHON     interpreter with wallycore (default: python3)
//              PLAYWRIGHT module name or path of playwright (default: playwright)
//
// The Jade side here is an independent encoder (see test_codec.js); the
// cryptography uses the same wally primitives as test_protocol.py.

"use strict";

const PW = require(process.env.PLAYWRIGHT || 'playwright');
const { execFileSync, spawn } = require('child_process');
const fs = require('fs'), os = require('os'), path = require('path'), zlib = require('zlib'), assert = require('assert');

const REPO = __dirname;
const ENGINE = process.argv[2] || 'chromium';
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sjps-browser-test-'));
const RUN = path.join(TMP, 'server');
const PY = process.env.PYTHON || 'python3';
let PORT = 0, BASE = '';     // a free port, chosen at start
const qrcode = require(path.join(REPO, 'qrcode.js'));

// ---- independent Jade side (same as test_codec.js) ----
const WORDS = fs.readFileSync(path.join(REPO, 'test_codec.js'), 'utf8').match(/const WORDS = "([a-z]+)"/)[1];
function refCbor(v) {
  const head = (m, n) => n < 24 ? [m << 5 | n] : n < 256 ? [m << 5 | 24, n] : [m << 5 | 25, n >> 8, n & 255];
  if (typeof v === 'number') return v < 65536 ? head(0, v) : [26, v >>> 24, (v >> 16) & 255, (v >> 8) & 255, v & 255];
  if (typeof v === 'string') { const b = [...Buffer.from(v, 'utf8')]; return [...head(3, b.length), ...b]; }
  if (v instanceof Uint8Array) return [...head(2, v.length), ...v];
  if (Array.isArray(v)) return [...head(4, v.length), ...v.flatMap(refCbor)];
  const k = Object.keys(v); return [...head(5, k.length), ...k.flatMap(x => [...refCbor(x), ...refCbor(v[x])])];
}
function refBw(bytes) { const c = zlib.crc32(Buffer.from(bytes)); return [...bytes, c >>> 24, (c >> 16) & 255, (c >> 8) & 255, c & 255].map(b => WORDS[b * 4] + WORDS[b * 4 + 3]).join(''); }
function refFragments(type, obj, max) {
  const msg = refCbor(obj);
  if (msg.length <= max) return ['ur:' + type + '/' + refBw(msg)];
  const count = Math.ceil(msg.length / max), size = Math.ceil(msg.length / count), crc = zlib.crc32(Buffer.from(msg));
  return Array.from({ length: count }, (_, i) => { const f = msg.slice(i * size, (i + 1) * size); while (f.length < size) f.push(0);
    return 'ur:' + type + '/' + (i + 1) + '-' + count + '/' + refBw(refCbor([i + 1, count, msg.length, crc, new Uint8Array(f)])); });
}
function jadeRequest(doc, data) {
  return { id: 'qrmode', result: { http_request: { params: { urls: [BASE + '/' + doc, 'http://pinserveronion.example/' + doc], method: 'POST', accept: 'json', data: { data } }, 'on-reply': 'pin' } } };
}

// ---- QR frames -> y4m video for Chromium's fake camera ----
function qrMatrix(text) { const q = qrcode(0, 'L'); q.addData(text.toUpperCase(), 'Alphanumeric'); q.make(); return q; }
function qrByteMatrix(text) { const q = qrcode(0, 'L'); q.addData(text, 'Byte'); q.make(); return q; }
// `crisp`: 600x450 video with an even module size. The page shows the camera at 300 px width and
// decodes from that size, so every QR module then covers a whole number of decoder pixels - the
// JavaScript decoder needs that with a synthetic, noise-free picture (a real camera image differs
// from frame to frame, a generated one is either always or never readable).
function writeVideo(file, qrs, crisp = false, framesEach = 8) {
  const W = crisp ? 600 : 640, H = crisp ? 450 : 480, uv = Buffer.alloc(W * H / 2, 128);
  const out = [Buffer.from(`YUV4MPEG2 W${W} H${H} F10:1 Ip A1:1 C420jpeg\n`)];
  for (const q of qrs) {
    const n = q.getModuleCount();
    const px = crisp ? 2 * Math.floor(400 / (n + 8) / 2) : Math.floor(420 / (n + 8));
    const size = n * px, x0 = (W - size) >> 1, y0 = (H - size) >> 1;
    const y = Buffer.alloc(W * H, 235);
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (q.isDark(r, c))
      for (let dy = 0; dy < px; dy++) y.fill(16, (y0 + r * px + dy) * W + x0 + c * px, (y0 + r * px + dy) * W + x0 + (c + 1) * px);
    for (let i = 0; i < framesEach; i++) out.push(Buffer.from('FRAME\n'), y, uv);
  }
  fs.writeFileSync(file, Buffer.concat(out));
}
function imgSrcFor(text) { return qrMatrix(text).createImgTag(4).match(/src="([^"]+)"/)[1]; }

const py = (...args) => execFileSync(PY, [path.join(REPO, 'test_browser_client.py'), ...args], { encoding: 'utf8' }).trim();
const sleep = ms => new Promise(r => setTimeout(r, ms));
let passed = 0;
const pass = name => { passed++; console.log('PASS ' + name); };

async function withPage(video, fn, options = {}) {
  const fake = '--use-fake-device-for-media-stream' + (options.cameras ? '=device-count=' + options.cameras : '');
  const args = ENGINE === 'chromium' ? ['--use-fake-ui-for-media-stream', fake, ...(video ? ['--use-file-for-fake-video-capture=' + video] : [])] : [];
  const browser = await PW[ENGINE].launch({ args });
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 } });
  await ctx.addInitScript(nativeDetector => {
    // decode with the JavaScript decoder if the scenario asks for it
    if (!nativeDetector) { try { delete window.BarcodeDetector; } catch (e) {} }
    // count camera openings: one tap must open exactly one camera stream
    window.__cameraOpenings = [];
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const original = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = constraints => { window.__cameraOpenings.push(JSON.stringify(constraints)); return original(constraints); };
    }
  }, !options.jsDecoder);
  const page = await ctx.newPage();
  const problems = [], posts = [];
  // The QR library rejects an internal promise when a camera is closed while its video is still
  // starting (a scenario stops or switches right after the start). Harmless; everything else counts.
  page.on('pageerror', e => { if (!/play\(\) request was interrupted/.test(e.message)) problems.push('pageerror: ' + e.message); });
  page.on('console', m => { if (m.type() === 'error' || /Content Security Policy|Refused to/i.test(m.text())) problems.push('console: ' + m.text()); });
  page.on('request', r => { if (r.method() === 'POST') posts.push(r.url()); });
  try { await fn(page, problems, posts); } finally { await browser.close(); }
}
// record every text the request row shows
const watchRow = page => page.evaluate(() => { window.__rows = []; new MutationObserver(() => window.__rows.push(document.getElementById('pin_request').textContent)).observe(document.getElementById('pin_request'), { childList: true, characterData: true, subtree: true }); });

async function collectReply(page) {
  await page.waitForSelector('#qr_tile:not([hidden]) img', { timeout: 120000 });
  const seen = new Set();
  for (let i = 0; i < 70; i++) { seen.add(await page.$eval('#qrcode2 img', e => e.getAttribute('src'))); await sleep(100); }
  const data = (await page.textContent('#pin_response')).replace(/^data: /, '');
  // the reply QR loop must be exactly the QR codes of the independently encoded reply message
  const msg = { id: '0', method: 'pin', params: { data } };
  const count = Math.ceil(refCbor(msg).length / 34);
  const expected = refFragments('jade-pin', msg, Math.ceil(refCbor(msg).length / count)).map(imgSrcFor);
  assert.deepStrictEqual([...seen].sort(), [...new Set(expected)].sort(), 'reply QR frames differ from the independent encoding');
  return data;
}

(async () => {
  // The server keeps key_data below its working directory: run it in the
  // temp directory so the test never touches a real key_data
  fs.mkdirSync(RUN);
  const log = fs.openSync(path.join(TMP, 'server.log'), 'w');
  // a port nobody else uses, so the test can never talk to a foreign server
  PORT = await new Promise(resolve => { const probe = require('net').createServer().listen(0, '127.0.0.1', () => { const p = probe.address().port; probe.close(() => resolve(p)); }); });
  BASE = 'http://127.0.0.1:' + PORT;
  const server = spawn(PY, [path.join(REPO, 'SimpleJadePinServer.py'), '--no-tls', '--port', String(PORT)], { cwd: RUN, stdio: ['ignore', log, log] });
  try {
    let up = false;
    for (let i = 0; i < 50 && !up; i++) { try { up = (await fetch(BASE + '/')).ok; } catch (e) {} if (!up) await sleep(200); }
    assert.ok(up && server.exitCode === null, 'server did not start: ' + fs.readFileSync(path.join(TMP, 'server.log'), 'utf8').slice(-400));
    const pub = fs.readFileSync(RUN + '/key_data/server_keys/public.key').toString('hex');
    const S = path.join(TMP, 'walletA.json');
    fs.rmSync(S, { force: true }); py('init', S, pub);
    const key = py('setpin', BASE, S);

    if (ENGINE === 'chromium') {
      // ---- A: unlock, one tap, with Jade-style extras (fountain-numbered parts, a foreign QR code)
      const dataA = py('prepare', 'get_pin', S);
      const fragsA = refFragments('jade-pin', jadeRequest('get_pin', dataA), 26);   // 26 bytes: the Jade's low QR density
      assert.ok(fragsA.length >= 5);
      const extra = n => 'ur:jade-pin/' + n + '-' + fragsA.length + '/' + refBw(refCbor([n, fragsA.length, 1, 1, new Uint8Array(20)]));
      const videoA = path.join(TMP, 'a.y4m');
      writeVideo(videoA, [qrByteMatrix('https://example.com/not-a-jade-code'), ...fragsA.map(qrMatrix), qrMatrix(extra(fragsA.length + 1)), qrMatrix(extra(fragsA.length + 2))], true);
      await withPage(videoA, async (page, problems, posts) => {
        await page.goto(BASE + '/'); await watchRow(page);
        assert.strictEqual(await page.$eval('#btn_step2', b => b.disabled), true);
        await page.click('#btn_scan');                                  // the only tap
        const reply = await collectReply(page);
        assert.strictEqual(py('verify', S, reply), key, 'unlock key mismatch');
        assert.deepStrictEqual(posts, [BASE + '/get_pin'], 'exactly one get_pin expected');
        assert.strictEqual(await page.$$eval('video', v => v.length), 0, 'camera still running after the scan');
        const openings = await page.evaluate(() => window.__cameraOpenings);
        assert.deepStrictEqual(openings, ['{"audio":false,"video":{"facingMode":"environment"}}'], 'one tap must open exactly one (rear) camera stream');
        assert.strictEqual(await page.textContent('#btn_scan'), 'Start scan');
        const rows = await page.evaluate(() => window.__rows);
        assert.ok(rows.some(t => /Fragment \d+ \/ \d+ captured/.test(t)), 'no fragment progress shown');
        assert.ok((await page.textContent('#pin_request')).startsWith('get_pin — data: '));
        assert.deepStrictEqual(problems, [], 'browser reported problems');
      }, { jsDecoder: true });
      pass('unlock with a single tap (JavaScript QR decoder): scan -> automatic get_pin -> reply QR decrypts to the stored key');

      // ---- B: the same (already used) request again -> visible error, no dead end
      await withPage(videoA, async (page, problems) => {
        await page.goto(BASE + '/');
        await page.click('#btn_scan');
        await page.waitForSelector('#pin_response.error', { timeout: 120000 });
        const text = await page.textContent('#pin_response');
        assert.ok(/rejected this request/.test(text) && /restart the unlock on the Jade/.test(text), text);
        assert.strictEqual(await page.$eval('#btn_step2', b => b.disabled), true, 'a used request must not be re-sendable');
        assert.strictEqual(await page.$eval('#qr_tile', e => e.hidden), true);
        assert.deepStrictEqual(problems.filter(p => !/400 \(Bad Request\)/.test(p)), []);
        // and a new scan can be started right away
        await page.click('#btn_scan'); await page.waitForSelector('video');
        assert.strictEqual(await page.textContent('#pin_response'), 'data: ?');
      });
      pass('rejected request (replay): clear message with what to do, page stays usable');

      // ---- C: server unreachable -> message + retry works
      const dataC = py('prepare', 'get_pin', S);
      const videoC = path.join(TMP, 'c.y4m');
      writeVideo(videoC, refFragments('jade-pin', jadeRequest('get_pin', dataC), 60).map(qrMatrix));
      await withPage(videoC, async (page, problems, posts) => {
        await page.goto(BASE + '/');
        await page.route('**/get_pin', r => r.abort());
        await page.click('#btn_scan');
        await page.waitForSelector('#pin_response.error', { timeout: 120000 });
        assert.ok(/could not be reached/.test(await page.textContent('#pin_response')));
        assert.strictEqual(await page.$eval('#btn_step2', b => b.disabled), false, 'retry must be possible');
        await page.unroute('**/get_pin');
        await page.click('#btn_step2');
        const reply = await collectReply(page);
        assert.strictEqual(py('verify', S, reply), key);
        assert.strictEqual(await page.$eval('#pin_response', e => e.classList.contains('error')), false);
      });
      pass('server unreachable: message shown, retry succeeds');

      // ---- D: a damaged scan is reported, nothing is sent, and the next clean pass succeeds
      const dataD = py('prepare', 'get_pin', S);
      const fragsD = refFragments('jade-pin', jadeRequest('get_pin', dataD), 60);
      const badD = fragsD.slice(); badD[1] = badD[1].slice(0, -3) + (badD[1].slice(-3, -2) === 'a' ? 'b' : 'a') + badD[1].slice(-2);
      const videoD = path.join(TMP, 'd.y4m');
      writeVideo(videoD, [qrByteMatrix('https://example.com/not-a-jade-code')]);
      await withPage(videoD, async (page, problems, posts) => {
        await page.goto(BASE + '/'); await watchRow(page);
        await page.click('#btn_scan');
        await page.waitForSelector('video');
        // hand the page a complete but damaged set of fragments, the way the scanner would
        // (independent of camera timing; real camera scanning is covered by the other scenarios)
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), badD);
        await page.waitForFunction(() => window.__rows.some(t => /^Invalid scan \((bytewords crc mismatch|invalid byteword)\)/.test(t)), null, { timeout: 10000 });
        assert.strictEqual(await page.$$eval('video', v => v.length), 1, 'camera must keep running after a damaged scan');
        assert.deepStrictEqual(posts, [], 'a damaged scan must never be sent');
        assert.strictEqual(await page.$eval('#btn_step2', b => b.disabled), true);
        // the Jade's next clean pass
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsD);
        const reply = await collectReply(page);
        assert.strictEqual(py('verify', S, reply), key);
        assert.deepStrictEqual(posts, [BASE + '/get_pin']);
      });
      pass('damaged scan is reported, nothing is sent, scanning continues and the next clean pass succeeds');

      // ---- D2: scan stopped by hand: a late frame must not send anything
      const dataD2 = py('prepare', 'get_pin', S);
      const fragsD2 = refFragments('jade-pin', jadeRequest('get_pin', dataD2), 60);
      await withPage(videoD, async (page, problems, posts) => {
        await page.goto(BASE + '/');
        await page.click('#btn_scan'); await page.waitForSelector('video');
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsD2.slice(0, -1));
        await page.click('#btn_scan');                                     // Stop scan
        await page.waitForFunction(() => document.querySelectorAll('video').length === 0);
        await page.evaluate(f => onScan(f.toUpperCase()), fragsD2[fragsD2.length - 1]);
        await sleep(800);
        assert.deepStrictEqual(posts, [], 'a frame arriving after "Stop scan" must not send a request');
        assert.strictEqual(await page.textContent('#btn_scan'), 'Start scan');
        assert.ok(/Scan stopped/.test(await page.textContent('#pin_request')));
      });
      pass('scan stopped by hand: nothing is sent afterwards');

      // ---- G: an error page from a proxy (HTTP 503) on an unlock: retry offered, no pin-limit talk
      const dataG = py('prepare', 'get_pin', S);
      const fragsG = refFragments('jade-pin', jadeRequest('get_pin', dataG), 60);
      await withPage(videoD, async (page) => {
        await page.goto(BASE + '/');
        await page.route('**/get_pin', r => r.fulfill({ status: 503, contentType: 'text/html', body: '<html>upstream unavailable</html>' }));
        await page.click('#btn_scan'); await page.waitForSelector('video');
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsG);
        await page.waitForSelector('#pin_response.error', { timeout: 10000 });
        const text = await page.textContent('#pin_response');
        assert.ok(/HTTP 503/.test(text) && !/MAX_PIN_FILES/.test(text), text);
        assert.strictEqual(await page.$eval('#btn_step2', b => b.disabled), false, 'retry must be possible after a proxy error');
        await page.unroute('**/get_pin');
        await page.click('#btn_step2');
        assert.strictEqual(py('verify', S, await collectReply(page)), key);
      });
      pass('proxy error (503) on an unlock: reported as such, retry succeeds');

      // ---- E: new PIN (set_pin) waits for an explicit tap
      const S2 = path.join(TMP, 'walletB.json');
      fs.rmSync(S2, { force: true }); py('init', S2, pub);
      const dataE = py('prepare', 'set_pin', S2);
      const videoE = path.join(TMP, 'e.y4m');
      writeVideo(videoE, refFragments('jade-pin', jadeRequest('set_pin', dataE), 60).map(qrMatrix));
      let newKey;
      await withPage(videoE, async (page, problems, posts) => {
        await page.goto(BASE + '/');
        await page.click('#btn_scan');
        await page.waitForFunction(() => !document.getElementById('btn_step2').disabled, null, { timeout: 120000 });
        await sleep(1500);
        assert.deepStrictEqual(posts, [], 'set_pin must not be sent without a tap');
        assert.ok((await page.textContent('#pin_request')).startsWith('set_pin — data: '));
        assert.ok(/Tap “Generate reply QR”/.test(await page.textContent('#pin_response')));
        await page.click('#btn_step2');
        const reply = await collectReply(page);
        newKey = py('verify', S2, reply);
        assert.strictEqual(newKey.length, 64);
        assert.deepStrictEqual(posts, [BASE + '/set_pin']);
        assert.deepStrictEqual(problems, []);
      });
      // the key handed out by set_pin is what a later unlock returns
      const dataE2 = py('prepare', 'get_pin', S2);
      const videoE2 = path.join(TMP, 'e2.y4m');
      writeVideo(videoE2, refFragments('jade-pin', jadeRequest('get_pin', dataE2), 60).map(qrMatrix));
      await withPage(videoE2, async (page) => {
        await page.goto(BASE + '/'); await page.click('#btn_scan');
        assert.strictEqual(py('verify', S2, await collectReply(page)), newKey);
      });
      pass('new PIN (set_pin): sent only after the explicit tap; later unlock returns the same key');

      // ---- H: a new scan is started while the previous answer is still pending
      const dataH1 = py('prepare', 'get_pin', S);           // request 1: answered late
      const fragsH1 = refFragments('jade-pin', jadeRequest('get_pin', dataH1), 60);
      const dataH2 = py('prepare', 'get_pin', S2);          // request 2: from the second wallet
      const fragsH2 = refFragments('jade-pin', jadeRequest('get_pin', dataH2), 60);
      await withPage(videoD, async (page, problems, posts) => {
        await page.goto(BASE + '/');
        let first = true;
        await page.route('**/get_pin', async r => { if (first) { first = false; await sleep(3000); } await r.continue(); });
        await page.click('#btn_scan'); await page.waitForSelector('video');
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsH1);
        await page.waitForFunction(() => /Contacting the server/.test(document.getElementById('pin_response').textContent));
        await page.click('#btn_scan'); await page.waitForSelector('video');        // new scan, request 1 still pending
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsH2);
        const reply = await collectReply(page);
        assert.strictEqual(py('verify', S2, reply), newKey, 'the reply shown must belong to the new request');
        await sleep(3500);                                                           // late answer 1 arrives now
        const after = (await page.textContent('#pin_response')).replace(/^data: /, '');
        assert.strictEqual(after, reply, 'a late answer of the earlier request replaced the current reply');
        assert.ok((await page.textContent('#pin_request')).includes(dataH2));
        assert.strictEqual(posts.length, 2, 'both requests must have been sent exactly once');
      });
      pass('new scan while an answer is pending: the new request is sent, the late answer is dropped');

      // ---- H2: the very same request is scanned again (the Jade still shows it),
      // first while its answer is pending, then after the answer arrived
      const dataH3 = py('prepare', 'get_pin', S);
      const fragsH3 = refFragments('jade-pin', jadeRequest('get_pin', dataH3), 60);
      await withPage(videoD, async (page, problems, posts) => {
        await page.goto(BASE + '/');
        await page.route('**/get_pin', async r => { await sleep(3000); await r.continue(); });
        await page.click('#btn_scan'); await page.waitForSelector('video');
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsH3);
        await page.waitForFunction(() => /Contacting the server/.test(document.getElementById('pin_response').textContent));
        await page.click('#btn_scan'); await page.waitForSelector('video');        // scan again, answer still pending
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsH3);
        const reply = await collectReply(page);
        assert.strictEqual(py('verify', S, reply), key, 'the pending answer must be shown for the repeated scan');
        assert.strictEqual(posts.length, 1, 'the same request was sent twice');
        await page.click('#btn_scan'); await page.waitForSelector('video');        // and once more, after the answer
        await page.waitForFunction(() => document.getElementById('qr_tile').hidden);
        await page.evaluate(fragments => fragments.forEach(f => onScan(f.toUpperCase())), fragsH3);
        assert.strictEqual(await collectReply(page), reply, 'the repeated scan must show the same answer again');
        assert.strictEqual(posts.length, 1, 'an already answered request was sent again');
        assert.deepStrictEqual(problems, []);
      });
      pass('same request scanned again (answer pending, answer received): sent once, answer shown');

      // ---- J: switching cameras cannot be raced with the scan button
      // (two generated test cameras; a video file would replace them by a single one)
      await withPage(null, async (page, problems) => {
        await page.goto(BASE + '/');
        await page.click('#btn_scan'); await page.waitForSelector('video');
        await page.waitForSelector('#btn_camera:not([hidden])', { timeout: 10000 });
        // switch and tap the scan button in the same instant
        await page.evaluate(() => { document.getElementById('btn_camera').click(); document.getElementById('btn_scan').click(); });
        await page.waitForFunction(() => !document.getElementById('btn_scan').disabled, null, { timeout: 15000 });
        await sleep(500);
        const state = await page.evaluate(() => ({
          label: document.getElementById('btn_scan').textContent,
          videos: document.querySelectorAll('video').length,
          live: [...document.querySelectorAll('video')].filter(v => v.srcObject && v.srcObject.getTracks().some(t => t.readyState === 'live')).length
        }));
        assert.deepStrictEqual(state, { label: 'Stop scan', videos: 1, live: 1 }, 'camera state inconsistent after switch + tap');
        await page.click('#btn_scan');                                               // and it can be stopped normally
        await page.waitForFunction(() => document.querySelectorAll('video').length === 0);
        assert.strictEqual(await page.textContent('#btn_scan'), 'Start scan');
        assert.deepStrictEqual(problems, []);
      }, { cameras: 2 });
      pass('camera switch: a simultaneous tap on the scan button leaves a consistent state');

      // ---- F: single-QR request (not animated)
      const dataF = py('prepare', 'get_pin', S);
      const videoF = path.join(TMP, 'f.y4m');
      writeVideo(videoF, refFragments('jade-pin', jadeRequest('get_pin', dataF), 100000).map(qrMatrix));
      await withPage(videoF, async (page) => {
        await page.goto(BASE + '/'); await page.click('#btn_scan');
        assert.strictEqual(py('verify', S, await collectReply(page)), key);
      });
      pass('single (non-animated) request QR works');
    }

    // ---- Oracle QR page (all engines)
    await withPage(null, async (page, problems) => {
      await page.goto(BASE + '/oracle_qr.html');
      assert.strictEqual(await page.inputValue('#urla'), BASE);
      assert.strictEqual(await page.inputValue('#pubkey'), pub);
      await page.click('#btn_generate');
      const src = await page.$eval('#generated_qrcode img', e => e.getAttribute('src'));
      const expected = 'ur:jade-updps/' + refBw(refCbor({ id: '001', method: 'update_pinserver', params: { urlA: BASE, urlB: '', pubkey: new Uint8Array(Buffer.from(pub, 'hex')) } }));
      assert.strictEqual(src, imgSrcFor(expected), 'Oracle QR differs from the independent encoding');
      // an invalid key is refused with a dialog instead of producing a QR code
      let dialog = null; page.on('dialog', d => { dialog = d.message(); d.dismiss(); });
      await page.fill('#pubkey', pub.slice(0, 60)); await page.click('#btn_generate'); await sleep(300);
      assert.ok(/66 hex characters/.test(dialog || ''), 'no warning for an invalid pubkey');
      assert.deepStrictEqual(problems, []);
    });
    pass('Oracle QR page: QR equals the independently encoded update_pinserver message (' + ENGINE + ')');

    // ---- PIN page without a camera: clear message instead of silence
    if (ENGINE !== 'chromium') {
      await withPage(null, async (page, problems) => {
        await page.goto(BASE + '/');
        assert.strictEqual(await page.textContent('#footer_host'), '127.0.0.1:' + PORT);
        await page.click('#btn_scan');
        await page.waitForSelector('#pin_request.error', { timeout: 15000 });
        assert.ok(/camera could not be started/i.test(await page.textContent('#pin_request')));
        assert.strictEqual(await page.textContent('#btn_scan'), 'Start scan');
        assert.deepStrictEqual(problems.filter(p => /Content Security Policy|Refused/i.test(p)), []);
      });
      pass('no camera available: clear message, no policy violations (' + ENGINE + ')');
    }
    console.log('ALL BROWSER TESTS PASSED (' + ENGINE + ', ' + passed + ' scenarios)');
  } finally {
    server.kill();
    fs.rmSync(TMP, { recursive: true, force: true });
  }
})().catch(e => { console.error('FAILED:', e.message || e); process.exit(1); });
