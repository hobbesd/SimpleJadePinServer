// Page logic of the PIN page (index.html): scan the Jade's PIN request,
// send it to this server, show the reply as an animated QR code.
//
// Flow:
//   1. "Start scan" opens the rear camera right away (one tap).
//   2. Once the Jade's request is complete and passes its checksums:
//        - get_pin (unlock): sent to the server automatically.
//        - set_pin (new PIN): waits for "Generate reply QR", because it
//          replaces what the server stores for this wallet.
//   3. The reply is shown as a QR loop for the Jade's camera.
// Every failure is reported in the page; nothing fails silently.

"use strict";

const UR_TYPE = "jade-pin";
const REPLY_FRAME_MS = 1000;
const REQUEST_TIMEOUT_MS = 20000;
const REPLY_AWAKE_MS = 5 * 60 * 1000;

let scanner = null;          // Html5Qrcode instance while the camera is running
let busyCount = 0;           // > 0 while the camera is being started, stopped or switched
let scanFinished = false;    // set once a complete request was decoded, or the scan was stopped
let cameras = [];            // filled after the first successful camera start
let cameraIndex = -1;
let requestFragments = null; // scanned fragments of the current PIN request
let requestData = null;      // payload for the server, from the scanned request
let pinFunc = null;          // "get_pin" or "set_pin"
let generation = 0;          // counts scans; an answer to an older scan's request is dropped
let pending = null;          // { generation, func, data } of the request waiting for its answer
let answered = null;         // { func, data, reply } of the last request the server answered
let replyTimer = null;
let wakeLock = null;
let keepAwake = false;
let awakeTimer = null;

function el(id) {
    return document.getElementById(id);
}

// All text goes through textContent: scanned QR data and server answers are
// untrusted input and must never be interpreted as HTML.
function setRow(id, text, isError) {
    const row = el(id);
    row.textContent = text;
    row.classList.toggle("error", Boolean(isError));
}

function describeError(e) {
    const text = String((e && e.message) || e || "unknown error");
    return text.length > 140 ? text.slice(0, 140) + "…" : text;
}

// While the camera is being started, stopped or switched, the camera buttons
// are locked: two of these operations must never overlap.
function setBusy(isBusy) {
    busyCount += isBusy ? 1 : -1;
    el("btn_scan").disabled = busyCount > 0;
    el("btn_camera").disabled = busyCount > 0;
}

// --- screen wake lock -------------------------------------------------

// Keeps the display on while scanning and while the reply is shown, so the
// phone does not dim or lock in the middle of an unlock. Not available in
// every browser; the page works the same without it.
async function requestWakeLock() {
    if (!keepAwake || wakeLock !== null || !("wakeLock" in navigator)) {
        return;
    }

    try {
        const lock = await navigator.wakeLock.request("screen");
        lock.addEventListener("release", function() {
            if (wakeLock === lock) {
                wakeLock = null;
            }
        });

        if (keepAwake && wakeLock === null) {
            wakeLock = lock;
        } else {
            lock.release();
        }
    } catch (e) {
        // refused (e.g. low battery mode): nothing to do
    }
}

function holdAwake() {
    if (awakeTimer !== null) {
        clearTimeout(awakeTimer);
        awakeTimer = null;
    }

    keepAwake = true;
    requestWakeLock();
}

// Keep the display on, but not forever (the page may be left open)
function holdAwakeFor(milliseconds) {
    holdAwake();
    awakeTimer = setTimeout(releaseAwake, milliseconds);
}

function releaseAwake() {
    if (awakeTimer !== null) {
        clearTimeout(awakeTimer);
        awakeTimer = null;
    }

    keepAwake = false;

    if (wakeLock !== null) {
        const lock = wakeLock;
        wakeLock = null;
        lock.release().catch(function() {});
    }
}

// --- step 1: scan ------------------------------------------------------

function resetStep2() {
    if (replyTimer !== null) {
        clearInterval(replyTimer);
        replyTimer = null;
    }

    // From here on, an answer to a request of an earlier scan is ignored
    generation++;
    requestData = null;
    pinFunc = null;
    el("btn_step2").disabled = true;
    el("qr_tile").hidden = true;
    el("qrcode2").textContent = "";
    setRow("pin_response", "data: ?");
}

async function startCamera(cameraConfig) {
    const instance = new Html5Qrcode("qrreader1", {
        formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
        verbose: false
    });

    try {
        await instance.start(cameraConfig, { fps: 10, qrbox: { width: 230, height: 230 } }, onScan, function() {});
    } catch (e) {
        el("qrreader1").textContent = "";
        throw e;
    }

    scanner = instance;
    el("btn_scan").textContent = "Stop scan";
}

async function stopCamera() {
    const running = scanner;
    scanner = null;
    el("btn_scan").textContent = "Start scan";
    el("btn_camera").hidden = true;

    if (running === null) {
        return;
    }

    try {
        await running.stop();
    } catch (e) {
        // already stopped
    }

    try {
        running.clear();
    } catch (e) {
        // nothing rendered
    }
}

async function toggleScan() {
    if (busyCount > 0) {
        return;
    }

    setBusy(true);

    try {
        if (scanner !== null) {
            // Manual stop: a frame still being decoded must not complete a request
            scanFinished = true;
            await stopCamera();
            releaseAwake();
            setRow("pin_request", "Scan stopped. No request scanned yet.");
            return;
        }

        requestFragments = null;
        scanFinished = false;
        cameraIndex = -1;
        resetStep2();
        setRow("pin_request", "Starting camera …");

        try {
            // The rear camera, without a camera picker or a second confirmation
            await startCamera({ facingMode: "environment" });
        } catch (e) {
            releaseAwake();
            setRow("pin_request", "The camera could not be started (" + describeError(e) + "). Allow camera access "
                + "for this page and try again. Browsers only grant camera access on HTTPS or localhost pages.", true);
            return;
        }

        if (scanFinished) {
            // A request was completed while the camera was still starting
            await stopCamera();
            return;
        }

        setRow("pin_request", "Camera running — hold the Jade’s QR codes in view.");
        holdAwake();
        await offerCameraSwitch();
    } finally {
        setBusy(false);
    }
}

// With more than one camera, offer to cycle through them (for devices where
// the default rear camera is not the right one). The camera list is read
// without opening a second camera stream: the permission was just granted
// for the running one, so names and ids are available.
async function offerCameraSwitch() {
    try {
        const devices = await navigator.mediaDevices.enumerateDevices();
        cameras = devices
            .filter(device => device.kind === "videoinput" && device.deviceId)
            .map(device => ({ id: device.deviceId, label: device.label }));
    } catch (e) {
        cameras = [];
    }

    if (scanner !== null && cameras.length > 1) {
        el("btn_camera").hidden = false;
    }
}

async function switchCamera() {
    if (busyCount > 0 || scanner === null || cameras.length < 2) {
        return;
    }

    setBusy(true);

    try {
        if (cameraIndex < 0) {
            // Find the camera that "rear camera" resolved to, so the first tap
            // really switches to a different one
            try {
                const activeId = scanner.getRunningTrackSettings().deviceId;
                cameraIndex = cameras.findIndex(camera => camera.id === activeId);
            } catch (e) {
                cameraIndex = -1;
            }
        }

        cameraIndex = (cameraIndex + 1) % cameras.length;
        await stopCamera();

        try {
            await startCamera({ deviceId: { exact: cameras[cameraIndex].id } });
        } catch (e) {
            releaseAwake();
            setRow("pin_request", "That camera could not be started (" + describeError(e) + "). Tap “Start scan” to use the default camera.", true);
            return;
        }

        if (scanFinished) {
            // The request was completed by a last frame of the previous camera
            await stopCamera();
            return;
        }

        el("btn_camera").hidden = false;
    } finally {
        setBusy(false);
    }
}

function onScan(result) {
    if (scanFinished) {
        return;
    }

    console.log("QRCode scanned: " + result);
    const result_split = result.split('/');

    if (result_split[0].toLowerCase() !== "ur:" + UR_TYPE) {
        setRow("pin_request", "That QR code is not a Jade PIN request. Show the code from the Jade’s “QR PIN Unlock” screen.", true);
        return;
    }

    if (result_split.length == 3) {
        const seq_split = result_split[1].split('-');
        const seq = parseInt(seq_split[0]);
        const numberOfFrags = parseInt(seq_split[1]);

        if (!(numberOfFrags >= 1) || !(seq >= 1)) {
            return;
        }

        // Fresh array if the fragment count changed (e.g. the Jade
        // was restarted mid-scan) so old and new fragments never mix
        if (requestFragments == null || requestFragments.length != numberOfFrags) {
            requestFragments = Array(numberOfFrags).fill(null);
        }

        // Fragments numbered beyond the count are the Jade's fountain-code
        // extras; this page only uses the plain numbered ones.
        if (seq > numberOfFrags) {
            return;
        }

        requestFragments[seq - 1] = result;
        const got = requestFragments.filter(fragment => fragment != null).length;

        if (got == numberOfFrags) {
            finishScan();
        } else {
            setRow("pin_request", "Fragment " + got + " / " + numberOfFrags + " captured …");
        }
    } else if (result_split.length == 2) {
        requestFragments = [result];
        finishScan();
    }
}

function finishScan() {
    let urls;
    let data;

    try {
        const decoded_object = bcur_decode_object(UR_TYPE, requestFragments);
        const params = decoded_object["result"]["http_request"]["params"];
        urls = params["urls"];
        data = params["data"]["data"];

        if (!Array.isArray(urls) || typeof data !== "string") {
            throw new Error("not a PIN request");
        }
    } catch (e) {
        // A mis-scan or a foreign QR code: forget it and keep scanning
        console.log("QR decode failed: " + e);
        requestFragments = null;
        setRow("pin_request", "Invalid scan (" + describeError(e) + ") — keep the Jade’s QR codes in view.", true);
        return;
    }

    scanFinished = true;
    stopCameraAfterScan();

    requestData = data;
    pinFunc = urls.some(url => typeof url === "string" && url.endsWith("set_pin")) ? "set_pin" : "get_pin";
    setRow("pin_request", pinFunc + " — data: " + requestData);

    if (pinFunc === "get_pin") {
        // Unlock: nothing to decide, send right away
        sendRequest();
    } else {
        // New PIN: replaces what the server stores for this wallet, so it
        // is only sent on an explicit tap
        el("btn_step2").disabled = false;
        setRow("pin_response", "New PIN setup scanned. Tap “Generate reply QR” to store it on this server.");
        holdAwakeFor(REPLY_AWAKE_MS);
    }
}

async function stopCameraAfterScan() {
    setBusy(true);

    try {
        await stopCamera();
    } finally {
        setBusy(false);
    }
}

// --- step 2: ask the server, show the reply ----------------------------

function fail(message, allowRetry) {
    setRow("pin_response", message, true);
    // A request can only be repeated when it may not have reached the
    // server; otherwise the Jade has to produce a new one.
    el("btn_step2").disabled = !allowRetry;
    releaseAwake();
}

const RESTART_HINT = " A PIN request can be used only once: restart the unlock on the Jade and scan its new QR code.";
const RETRY_HINT = " Tap “Generate reply QR” to try again. If the retry is rejected, the first attempt did arrive: restart the unlock on the Jade.";

async function sendRequest() {
    if (requestData === null || pinFunc === null) {
        return;
    }

    const func = pinFunc;
    const data = requestData;

    // Guard against sending a request twice: every request burns a replay
    // counter step, and a repeated set_pin re-randomizes the stored key
    // server-side (upstream parity), which would break the pairing.
    if (answered !== null && answered.func === func && answered.data === data) {
        // The same request was scanned again (the Jade still shows it) and
        // the server has answered it already: show that answer again
        el("btn_step2").disabled = true;
        showReply(answered.reply);
        return;
    }

    if (pending !== null && pending.func === func && pending.data === data) {
        // Still waiting for the answer to this very request - also when it
        // was scanned again in the meantime: the answer now belongs to the
        // current scan
        pending.generation = generation;
        el("btn_step2").disabled = true;
        setRow("pin_response", "Contacting the server …");
        holdAwake();
        return;
    }

    // The request belongs to the scan it came from. If a different request
    // is scanned before the answer arrives, the answer is not shown (see
    // requestReply) and the new request is sent on its own.
    const job = { generation: generation, func: func, data: data };

    pending = job;
    el("btn_step2").disabled = true;
    setRow("pin_response", "Contacting the server …");
    holdAwake();

    try {
        await requestReply(job);
    } finally {
        if (pending === job) {
            pending = null;
        }
    }
}

async function requestReply(job) {
    const func = job.func;
    let response;
    let reply;
    const controller = new AbortController();
    // The time limit covers the whole answer, headers and body
    const timer = setTimeout(function() { controller.abort(); }, REQUEST_TIMEOUT_MS);

    try {
        response = await fetch(func, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ "data": job.data }),
            cache: "no-store",
            signal: controller.signal
        });

        if (response.status === 200) {
            try {
                reply = (await response.json()).data;
            } catch (e) {
                if (controller.signal.aborted) {
                    throw e;
                }

                reply = undefined;
            }
        }
    } catch (e) {
        if (job.generation === generation) {
            fail("The server could not be reached or did not answer in time. Check the connection." + RETRY_HINT, true);
        }

        return;
    } finally {
        clearTimeout(timer);
    }

    if (response.status === 200 && typeof reply === "string" && reply.length > 0) {
        // Remembered even when a new scan was started in the meantime: if
        // that scan turns out to be this same request, its answer is here
        answered = { func: func, data: job.data, reply: reply };
    }

    if (job.generation !== generation) {
        // A new scan was started in the meantime; this answer is not shown
        return;
    }

    if (response.status === 400) {
        fail("The server rejected this request: it was already used, it does not belong to this server, "
            + "or the server could not process it." + RESTART_HINT + " If a fresh request is rejected too, check the server log.", false);
        return;
    }

    if (response.status === 403) {
        fail("The server refused the request because this page was opened under an address it does not expect. "
            + "Open the page under the server’s own address (or add this one to ALLOWED_ORIGINS on the server).", false);
        return;
    }

    if (response.status === 503 && func === "set_pin") {
        // Only a new PIN can run into the pin limit; any other 503 comes
        // from something in front of the server and is handled below
        fail("The new PIN was not stored. If this server holds its maximum number of PINs (MAX_PIN_FILES), "
            + "old pin files have to be removed first; otherwise the server was briefly unavailable." + RETRY_HINT, true);
        return;
    }

    if (response.status !== 200) {
        fail("The server did not answer as expected (HTTP " + response.status + ")." + RETRY_HINT, true);
        return;
    }

    if (typeof reply !== "string" || reply.length === 0) {
        fail("The server’s answer could not be read." + RESTART_HINT, false);
        return;
    }

    showReply(reply);
}

function render_alphanumeric_qrcode(element_id, data) {
    let qr = qrcode(0, 'L');
    qr.addData(data.toUpperCase(), 'Alphanumeric');
    qr.make();
    // Markup generated by qrcode.js from our own encoder output (an <img>
    // with a data: URL), not from scanned or server-supplied text
    el(element_id).innerHTML = qr.createImgTag(4);
}

function showReply(data) {
    setRow("pin_response", "data: " + data);

    const fragments = bcur_encode_fragments(UR_TYPE, {
        "id": "0",
        "method": "pin",
        "params": {
            "data": data
        }
    });

    if (replyTimer !== null) {
        clearInterval(replyTimer);
    }

    let index = 0;
    render_alphanumeric_qrcode("qrcode2", fragments[0]);
    el("qr_tile").hidden = false;

    replyTimer = setInterval(function() {
        index = (index + 1) % fragments.length;
        render_alphanumeric_qrcode("qrcode2", fragments[index]);
    }, REPLY_FRAME_MS);

    // Keep the display on while the Jade scans the reply
    holdAwakeFor(REPLY_AWAKE_MS);

    // With the automatic send the reply appears without a tap: bring it into view
    el("qr_tile").scrollIntoView({ behavior: "smooth", block: "center" });
}

// --- wiring --------------------------------------------------------------

el("btn_scan").addEventListener("click", toggleScan);
el("btn_camera").addEventListener("click", switchCamera);
el("btn_step2").addEventListener("click", sendRequest);
el("btn_reload").addEventListener("click", function() { location.reload(); });
el("footer_host").textContent = location.host;

// A wake lock is dropped whenever the page is hidden; take it again on return
document.addEventListener("visibilitychange", function() {
    if (document.visibilityState === "visible") {
        requestWakeLock();
    }
});
