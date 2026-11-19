#!/usr/bin/env node
// Tests for jade-codec.js (the BC-UR / CBOR / Bytewords code of the web pages).
//
//     node test_codec.js
//
// The "Jade side" in these tests is an independent encoder written from the
// specifications (RFC 8949 CBOR, BCR-2020-005 UR, BCR-2020-012 Bytewords,
// CRC32 from zlib). It shares no code with jade-codec.js, so an error in the
// codec is not mirrored by the test.
//
// NOTE: like test_protocol.py, this cannot prove compatibility with a real
// device; the anchor for that is an actual unlock with a Jade.

"use strict";

const assert = require("assert");
const zlib = require("zlib");
const codec = require("./jade-codec.js");

let checks = 0;

function pass(name) {
    checks++;
    console.log("PASS " + name);
}

// --- independent reference implementation -----------------------------

const WORDS = "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom";

function refCbor(value) {
    const head = (major, n) =>
        n < 24 ? [major << 5 | n]
        : n < 256 ? [major << 5 | 24, n]
        : n < 65536 ? [major << 5 | 25, n >> 8, n & 255]
        : [major << 5 | 26, n >>> 24, (n >> 16) & 255, (n >> 8) & 255, n & 255];

    if (typeof value === "number") return head(0, value);
    if (typeof value === "string") { const b = [...Buffer.from(value, "utf8")]; return [...head(3, b.length), ...b]; }
    if (value instanceof Uint8Array) return [...head(2, value.length), ...value];
    if (Array.isArray(value)) return [...head(4, value.length), ...value.flatMap(refCbor)];

    const keys = Object.keys(value);
    return [...head(5, keys.length), ...keys.flatMap(k => [...refCbor(k), ...refCbor(value[k])])];
}

function refBytewords(bytes) {
    const crc = zlib.crc32(Buffer.from(bytes));
    const all = [...bytes, crc >>> 24, (crc >> 16) & 255, (crc >> 8) & 255, crc & 255];
    return all.map(b => WORDS[b * 4] + WORDS[b * 4 + 3]).join("");
}

// What a Jade shows: one QR code if the message fits, otherwise numbered fragments
function refFragments(type, object, maxFragmentLength) {
    const message = refCbor(object);

    if (message.length <= maxFragmentLength) {
        return ["ur:" + type + "/" + refBytewords(message)];
    }

    const count = Math.ceil(message.length / maxFragmentLength);
    const size = Math.ceil(message.length / count);
    const crc = zlib.crc32(Buffer.from(message));
    const out = [];

    for (let i = 0; i < count; i++) {
        const fragment = message.slice(i * size, (i + 1) * size);
        while (fragment.length < size) fragment.push(0);
        out.push("ur:" + type + "/" + (i + 1) + "-" + count + "/"
            + refBytewords(refCbor([i + 1, count, message.length, crc, new Uint8Array(fragment)])));
    }

    return out;
}

// Deterministic pseudo-random bytes (the tests must be reproducible)
let seed = 0x1234abcd;

function randomBytes(n) {
    const out = new Uint8Array(n);

    for (let i = 0; i < n; i++) {
        seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
        out[i] = seed >>> 24;
    }

    return out;
}

const base64 = n => Buffer.from(randomBytes(n)).toString("base64");
const hex = bytes => Buffer.from(bytes).toString("hex");

// The message a Jade sends in QR mode (main/process/process_utils.c in the firmware)
function pinRequest(document, dataLength, urlCount) {
    return {
        "id": "qrmode",
        "result": {
            "http_request": {
                "params": {
                    "urls": ["https://pinserver.example:8443/" + document, "http://pinserveronion.example/" + document].slice(0, urlCount),
                    "method": "POST",
                    "accept": "json",
                    "data": { "data": base64(dataLength) }
                },
                "on-reply": "pin"
            }
        }
    };
}

// --- 1. official test vectors -------------------------------------------

// BCR-2020-012 (Bytewords): 16 payload bytes + CRC32 feac0dea in minimal encoding
{
    const payload = codec.decode_bytewords_checked("staslplabghydrpfmkbggufgludprfgmzepsbtwd");
    assert.strictEqual(hex(payload), "c7098580125e2ab0981253468b2dbc52");
    assert.strictEqual(codec.crc32(payload), 0xfeac0dea);
    // the same bytes inside a tagged CBOR structure, from the same document
    const tagged = codec.decode_bytewords_checked("tantjzoeadgdstaslplabghydrpfmkbggufgludprfgmaosecffltnsoaawkbd");
    assert.strictEqual(hex(tagged), "d99d6ca20150c7098580125e2ab0981253468b2dbc5202c11947da");
    assert.strictEqual(codec.crc32(tagged), 0xc904f40b);
    pass("Bytewords specification vectors");
}

// BCR-2020-005 (UR): single-part body and the first part of a multi-part UR
{
    assert.strictEqual(hex(codec.decode_bytewords_checked("oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox")),
        "a10150c7098580125e2ab0981253468b2dbc52");

    const whole = codec.decode_bytewords_checked("oyadhdeynteelblrcygldwvarflojtcywyjytpdkfwprylienshnjnpluypmamtkmybsjkspvseesawmrltdlnlgkplfbkqzzoglfeoyaegslobemohs");
    const part = codec.cbor_decode(new codec.BufferReader(
        codec.decode_bytewords_checked("lpadaxcsencylobemohsgmoyadhdeynteelblrcygldwvarflojtcywyjydmylgdsa")));
    assert.strictEqual(part[0], 1, "sequence number");
    assert.strictEqual(part[1], 3, "sequence length");
    assert.strictEqual(part[2], whole.length, "message length");
    assert.strictEqual(part[3], codec.crc32(whole), "message checksum");
    assert.strictEqual(hex(part[4]), hex(whole.subarray(0, part[4].length)), "fragment data");
    pass("UR specification vectors (single-part and multi-part)");
}

// --- 2. output is unchanged from the previous inline page code -----------

// Recorded from the page code before it was moved into jade-codec.js
{
    const replyData = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3PkVMU1phaG92fYSLkpmgp661vMPK0djf5u30+wIJEBceJSwzOkFIT1ZdZGtyeYCHjpWc";
    assert.deepStrictEqual(codec.bcur_encode_fragments("jade-pin", { "id": "0", "method": "pin", "params": { "data": replyData } }), [
        "ur:jade-pin/1-5/lpadahcsnbcymnmdkktehdcxotidiniehsdyiyjnihjyisjlieiajoinjtiyjohsjphsjnjkoyieiehsjyhskslaeepslbeh",
        "ur:jade-pin/2-5/lpaoahcsnbcymnmdkktehdcxfpktjlgmflfwetjngsghgyemgyjejzgyhfehecjzidfdgleniohkingdjzjoeyjevoynjznl",
        "ur:jade-pin/3-5/lpaxahcsnbcymnmdkktehdcxjsemgrecktgtiygwehieknimenkofdeedlkthkglfgfwjkingrghfpeogdjehfgtrhstdmae",
        "ur:jade-pin/4-5/lpaaahcsnbcymnmdkktehdcxgoehjoishsfleseyiyhkgugsjejojniojoenenehkogtgdgrdyieimiyeckpeodyidvsjpcf",
        "ur:jade-pin/5-5/lpahahcsnbcymnmdkktehdcxdnktgagefefwiaihgeguktkngwjefggaghehhtiehtfljykkihhkfxfdimjohgialnwnlfol"
    ]);
    assert.strictEqual(codec.bcur_encode_single("jade-updps", {
        "id": "001",
        "method": "update_pinserver",
        "params": {
            "urlA": "https://pinserver.example:8443",
            "urlB": "",
            "pubkey": codec.fromHexString("023447839124dc14d6007774399f4dc10ab3596a70c8d75dd9bae9998453784877")
        }
    }), "ur:jade-updps/otidinieiadydyehiyjnihjyisjliejokpjoiehsjyihhejoinjtjkihjpkoihjpiyjohsjphsjnjkotiekpjpjzfpksckisjyjyjojkftdldljoinjtjkihjpkoihjpdmihkshsjnjojzihfteteeeeeoiekpjpjzfwhniyjokpidjeihkkhdclaoeefllsmedkuobbtbaektjyesnegtsebkqdhkimjosptshltardwlnllrguksfdktkevolsbe");
    pass("reply QR and Oracle QR output unchanged (recorded vectors)");
}

// --- 3. decoding what a Jade sends ----------------------------------------

{
    let decoded = 0;

    for (let i = 0; i < 400; i++) {
        const request = pinRequest(i % 2 ? "set_pin" : "get_pin", 60 + i, 1 + (i % 2));
        // fragment sizes from tiny to "fits one QR code"
        const fragments = refFragments("jade-pin", request, i % 5 === 0 ? 100000 : 20 + (i % 90));
        assert.deepStrictEqual(codec.bcur_decode_object("jade-pin", fragments), request, "request " + i);
        // QR codes in alphanumeric mode are upper-case
        assert.deepStrictEqual(codec.bcur_decode_object("jade-pin", fragments.map(f => f.toUpperCase())), request, "upper-case request " + i);
        decoded += 2;
    }

    pass("decodes Jade-style PIN requests from an independent encoder (" + decoded + " messages, 1 to many fragments)");
}

// --- 4. damaged scans are rejected, never silently accepted -----------------

{
    let rejected = 0;

    for (let i = 0; i < 300; i++) {
        const request = pinRequest("get_pin", 150 + i, 2);
        const fragments = refFragments("jade-pin", request, i % 4 === 0 ? 100000 : 40 + (i % 50));
        const k = i % fragments.length;
        const body = fragments[k].lastIndexOf("/") + 1;
        const pos = body + (i * 7) % (fragments[k].length - body);
        const original = fragments[k][pos];
        // replace one letter by a different one
        fragments[k] = fragments[k].slice(0, pos) + (original === "a" ? "b" : "a") + fragments[k].slice(pos + 1);
        assert.throws(() => codec.bcur_decode_object("jade-pin", fragments), undefined, "corrupted fragment accepted (" + i + ")");
        rejected++;
    }

    // a fragment swapped in from another message: its own CRC is fine, the message CRC is not
    const requestA = pinRequest("get_pin", 200, 2);
    const requestB = pinRequest("get_pin", 200, 2);
    const a = refFragments("jade-pin", requestA, 60);
    const b = refFragments("jade-pin", requestB, 60);
    assert.strictEqual(a.length, b.length);
    const size = Math.ceil(refCbor(requestA).length / a.length);
    const slice = (request, i) => hex(refCbor(request).slice(i * size, (i + 1) * size));
    // a fragment before the last one whose payload really differs between the two messages
    const differing = a.findIndex((_, i) => i < a.length - 1 && slice(requestA, i) !== slice(requestB, i));
    assert.ok(differing >= 0, "need a differing fragment before the last one");
    a[differing] = b[differing];
    assert.throws(() => codec.bcur_decode_object("jade-pin", a), /message crc mismatch/);

    // wrong UR type, truncated body
    assert.throws(() => codec.bcur_decode_object("jade-pin", ["ur:bytes/" + refBytewords(refCbor({ "a": 1 }))]), /ur:jade-pin/);
    assert.throws(() => codec.bcur_decode_object("jade-pin", ["ur:jade-pin/ab"]), /length invalid/);
    pass("damaged or foreign scans are rejected (" + (rejected + 4) + " cases)");
}

// --- 5. encoding -----------------------------------------------------------

{
    for (let i = 0; i < 300; i++) {
        // includes strings of 256+ characters (two-byte length) and non-ASCII text
        const reply = { "id": String(i), "method": "pin", "params": { "data": base64(1 + i * 2), "note": i % 3 ? "plain" : "zwölf €" } };
        assert.deepStrictEqual([...codec.cbor_encode_object(reply)], refCbor(reply), "CBOR " + i);

        const fragments = codec.bcur_encode_fragments("jade-pin", reply);
        const fragmentLength = fragments.length === 1 ? 100000 : Math.ceil(refCbor(reply).length / fragments.length);
        assert.deepStrictEqual(fragments, refFragments("jade-pin", reply, fragmentLength), "fragments " + i);
        assert.deepStrictEqual(codec.bcur_decode_object("jade-pin", fragments), reply, "round trip " + i);

        // every fragment fits the QR size the page uses (34 payload bytes per fragment)
        for (const fragment of fragments) {
            assert.ok(fragments.length === 1 || fragment.length <= 130, "fragment too long: " + fragment.length);
        }
    }

    assert.throws(() => codec.cbor_encode_object({ "data": "x".repeat(70000) }), /too long/);
    pass("encoder matches the independent encoder, long and non-ASCII strings included");
}

console.log("ALL CODEC TESTS PASSED (" + checks + " groups)");
