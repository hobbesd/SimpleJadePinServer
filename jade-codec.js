// BC-UR / CBOR / Bytewords codec shared by the PIN page and the Oracle QR page.
//
// The Jade speaks to the pin server through "ur:jade-pin/..." QR codes
// (BC-UR: a CBOR message, Bytewords-encoded, optionally split into numbered
// fragments, each protected by a CRC32). This file only encodes and decodes
// that transport format; it contains no cryptography.
//
// Loaded as a plain script in the browser. Under Node (tests) the same file
// is loaded as a CommonJS module, see the export block at the end.
//
// Bytewords word list: Blockchain Commons, BSD-2-Clause-Patent (see LICENSE).

"use strict";

class BufferReader {
    constructor(buffer) {
        this.buffer = buffer;
        this.pos = 0;
    }

    peekByte() {
        return this.buffer[this.pos];
    }

    readByte() {
        return this.buffer[this.pos++];
    }

    readUint16() {
        var result = (this.buffer[this.pos] << 8) | this.buffer[this.pos + 1];
        this.pos += 2;
        return result;
    }

    readUint32() {
        // >>> 0 keeps the result unsigned; JS shifts are 32-bit
        var result = ((this.buffer[this.pos] << 24) | (this.buffer[this.pos + 1] << 16) | (this.buffer[this.pos + 2] << 8) | this.buffer[this.pos + 3]) >>> 0;
        this.pos += 4;
        return result;
    }

    readUint64() {
        var hi = this.readUint32();
        var lo = this.readUint32();
        return hi * 4294967296 + lo;
    }

    readChunk(length) {
        var result = new Uint8Array(length);

        for (let i = 0; i < length; ++i) {
            result[i] = this.buffer[this.pos + i];
        }

        this.pos += length;
        return result;
    }
}

class BufferWriter {
    constructor() {
        this.buffer = new Uint8Array(0);
    }

    writeByte(value) {
        let new_buffer = new Uint8Array(this.buffer.length + 1);
        new_buffer.set(this.buffer);
        new_buffer[this.buffer.length] = value & 0xFF;
        this.buffer = new_buffer;
    }

    writeUint16(value) {
        let new_buffer = new Uint8Array(this.buffer.length + 2);
        new_buffer.set(this.buffer);
        new_buffer[this.buffer.length] = (value >> 8) & 0xFF;
        new_buffer[this.buffer.length + 1] = value & 0xFF;
        this.buffer = new_buffer;
    }

    writeUint32(value) {
        let new_buffer = new Uint8Array(this.buffer.length + 4);
        new_buffer.set(this.buffer);
        new_buffer[this.buffer.length] = (value >> 24) & 0xFF;
        new_buffer[this.buffer.length + 1] = (value >> 16) & 0xFF;
        new_buffer[this.buffer.length + 2] = (value >> 8) & 0xFF;
        new_buffer[this.buffer.length + 3] = value & 0xFF;
        this.buffer = new_buffer;
    }

    writeUint64(value) {
        let new_buffer = new Uint8Array(this.buffer.length + 8);
        new_buffer.set(this.buffer);
        new_buffer[this.buffer.length] = (value >> 56) & 0xFF;
        new_buffer[this.buffer.length + 1] = (value >> 48) & 0xFF;
        new_buffer[this.buffer.length + 2] = (value >> 40) & 0xFF;
        new_buffer[this.buffer.length + 3] = (value >> 32) & 0xFF;
        new_buffer[this.buffer.length + 4] = (value >> 24) & 0xFF;
        new_buffer[this.buffer.length + 5] = (value >> 16) & 0xFF;
        new_buffer[this.buffer.length + 6] = (value >> 8) & 0xFF;
        new_buffer[this.buffer.length + 7] = value & 0xFF;
        this.buffer = new_buffer;
    }

    writeChunk(chunk) {
        let new_buffer = new Uint8Array(this.buffer.length + chunk.length);
        new_buffer.set(this.buffer);

        for (let i = 0; i < chunk.length; ++i) {
            new_buffer[this.buffer.length + i] = chunk[i];
        }

        this.buffer = new_buffer;
    }

    writeString(str) {
        let new_buffer = new Uint8Array(this.buffer.length + str.length);
        new_buffer.set(this.buffer);

        for (let i = 0; i < str.length; ++i) {
            new_buffer[this.buffer.length + i] = str.charCodeAt(i);
        }

        this.buffer = new_buffer;
    }

    getBuffer() {
        return this.buffer;
    }
}

const CborType = {
    Uint: 0,
    Bytes: 2,
    String: 3,
    Array: 4,
    Object: 5
};

// Write the head of a CBOR item: major type plus a length/count, in the
// shortest form. Lengths up to 65535 are supported; nothing this server
// produces comes close, and a longer item is refused instead of being
// written with a truncated length.
function cbor_write_head(buffer_writer, major_type, length) {
    if (length < 24) {
        buffer_writer.writeByte((major_type << 5) | length);
    } else if (length < 256) {
        buffer_writer.writeByte((major_type << 5) | 24);
        buffer_writer.writeByte(length);
    } else if (length < 65536) {
        buffer_writer.writeByte((major_type << 5) | 25);
        buffer_writer.writeUint16(length);
    } else {
        throw new Error("CBOR item too long");
    }
}

function cbor_encode_string(data) {
    let buffer_writer = new BufferWriter();
    // CBOR text strings are UTF-8; the length counts bytes, not characters
    const utf8 = new TextEncoder().encode(data);
    cbor_write_head(buffer_writer, 3, utf8.length);
    buffer_writer.writeChunk(utf8);

    return buffer_writer.getBuffer();
}

function cbor_encode_bytes(data) {
    let buffer_writer = new BufferWriter();
    cbor_write_head(buffer_writer, 2, data.length);
    buffer_writer.writeChunk(data);

    return buffer_writer.getBuffer();
}

function cbor_encode_uint(data) {
    let buffer_writer = new BufferWriter();

    if (data < 24) {
        buffer_writer.writeByte(data);
    } else if (data < 256) {
        buffer_writer.writeByte(24);
        buffer_writer.writeByte(data);
    } else if (data < 65536) {
        buffer_writer.writeByte(25);
        buffer_writer.writeUint16(data);
    } else if (data < 4294967296) {
        buffer_writer.writeByte(26);
        buffer_writer.writeUint32(data);
    } else {
        buffer_writer.writeByte(27);
        buffer_writer.writeUint64(data);
    }

    return buffer_writer.getBuffer();
}

function growUint8Array(originalArray, additionalSize) {
    let newSize = originalArray.length + additionalSize;
    let newArray = new Uint8Array(newSize);
    newArray.set(originalArray);
    return newArray;
}

function cbor_encode_array(data) {
    let buffer_writer = new BufferWriter();
    cbor_write_head(buffer_writer, 4, data.length);

    for (let i = 0; i < data.length; ++i) {
        let item;

        if (typeof data[i] == "number") {
            item = cbor_encode_uint(data[i]);
        } else if (data[i].constructor == Uint8Array) {
            item = cbor_encode_bytes(data[i]);
        }

        buffer_writer.writeChunk(item);
    }

    return buffer_writer.getBuffer();
}

function cbor_encode_object(data) {
    let buffer_writer = new BufferWriter();
    let keys = Object.keys(data);
    cbor_write_head(buffer_writer, 5, keys.length);

    for (let i = 0; i < keys.length; ++i) {
        let item;

        // Key
        if (typeof keys[i] == "number") {
            item = cbor_encode_uint(keys[i]);
        } else if (typeof keys[i] == "string") {
            item = cbor_encode_string(keys[i]);
        } else if (keys[i].constructor == Uint8Array) {
            item = cbor_encode_bytes(keys[i]);
        }

        buffer_writer.writeChunk(item);

        // Value
        let value = data[keys[i]];

        if (typeof value == "number") {
            item = cbor_encode_uint(value);
        } else if (typeof value == "string") {
            item = cbor_encode_string(value);
        } else if (value.constructor == Uint8Array) {
            item = cbor_encode_bytes(value);
        } else {
            item = cbor_encode_object(value);
        }

        buffer_writer.writeChunk(item);
    }

    return buffer_writer.getBuffer();
}

function cbor_read_header_value(reader) {
    var value = reader.readByte() & 0x1f;

    if (value < 24) {
        return value;
    } else if (value == 24) {
        return reader.readByte();
    } else if (value == 25) {
        return reader.readUint16();
    } else if (value == 26) {
        return reader.readUint32();
    } else if (value == 27) {
        return reader.readUint64();
    }

    return null;
}

function cbor_decode(reader) {
    let type = reader.peekByte() >> 5;

    switch (type) {
        case CborType.Uint:
            return cbor_read_header_value(reader);
        case CborType.Bytes:
            var len = cbor_read_header_value(reader);
            return reader.readChunk(len);
        case CborType.String:
            var len = cbor_read_header_value(reader);
            return new TextDecoder().decode(reader.readChunk(len));
        case CborType.Array:
            var len = cbor_read_header_value(reader);
            var result = [];

            for (let i = 0; i < len; ++i) {
                result[i] = cbor_decode(reader);
            }

            return result;
        case CborType.Object:
            var len = cbor_read_header_value(reader);
            var result = {};

            for (let i = 0; i < len; ++i) {
                var key = cbor_decode(reader);
                var value = cbor_decode(reader);
                result[key] = value;
            }

            return result;
    }

    return null;
}

function splitUint8Array(uInt8Array, length) {
    const result = [];
    const arrayLength = uInt8Array.length;

    for (let i = 0; i < arrayLength; i += length) {
        const chunk = uInt8Array.subarray(i, i + length);
        result.push(chunk);
    }

    return result;
}

const fromHexString = (hexString) =>
Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));

const toHexString = (bytes) =>
bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

const bytewords = 'ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabiasbluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcostcruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdulldutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfishfizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglowgoodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhopehornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowljudojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamblavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmanymathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnotenumbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolposepuffpumapurrquadquizraceramprealredorichroadrockroofrubyruinrunsrustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotasktaxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuservastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebswhatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom';
var bytewordsLookUpTable = [];
const BYTEWORDS_NUM = 256;
const BYTEWORD_LENGTH = 4;
const MINIMAL_BYTEWORD_LENGTH = 2;

function getWord(index) {
    return bytewords.slice(index * BYTEWORD_LENGTH, (index * BYTEWORD_LENGTH) + BYTEWORD_LENGTH)
}

function getMinimalWord(index) {
    const byteword = getWord(index);

    return byteword[0] + byteword[BYTEWORD_LENGTH - 1];
}

function decodeWord(word) {
    if (bytewordsLookUpTable.length == 0) {
        bytewordsLookUpTable = Array(26);

        for (let i = 0; i < BYTEWORDS_NUM; i++) {
            const byteword = getWord(i);
            let x = byteword[0].charCodeAt(0) - 'a'.charCodeAt(0);
            let y = byteword[3].charCodeAt(0) - 'a'.charCodeAt(0);
            let offset = y * 26 + x;
            bytewordsLookUpTable[offset] = i;
        }
    }

    let x = (word[0]).toLowerCase().charCodeAt(0) - 'a'.charCodeAt(0);
    let y = (word[word.length - 1]).toLowerCase().charCodeAt(0) - 'a'.charCodeAt(0);
    let offset = y * 26 + x;
    let value = bytewordsLookUpTable[offset];

    return value;
}

function makeCRCTable() {
    let c;
    let crcTable = [];

    for (let n = 0; n < 256; n++) {
        c = n;
        for (let k = 0; k < 8; k++) {
            c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
        }
        crcTable[n] = c;
    }

    return crcTable;
}

let crcTableCache = null;

function crc32(str) {
    let crcTable = crcTableCache || (crcTableCache = makeCRCTable());
    let crc = 0 ^ (-1);

    for (let i = 0; i < str.length; i++) {
        crc = (crc >>> 8) ^ crcTable[(crc ^ str[i]) & 0xFF];
    }

    return (crc ^ (-1)) >>> 0;
}

// Encode `input` as BC-UR of the given type (e.g. "jade-pin"). Returns an
// array of QR payloads: one element if the message fits a single fragment,
// otherwise numbered fragments ("ur:<type>/<seq>-<count>/...") to be shown
// in a loop.
function bcur_encode_fragments(type, input) {
    var ur = cbor_encode_object(input);

    const maxFragmentLength = 34;
    const minFragmentLength = 10;
    var seqNum = 0;

    const maxFragmentCount = Math.ceil(ur.length / minFragmentLength);
    var fragmentLength = 0;

    for (let fragmentCount = 1; fragmentCount <= maxFragmentCount; fragmentCount++) {
        fragmentLength = Math.ceil(ur.length / fragmentCount);
        if (fragmentLength <= maxFragmentLength) {
            break;
        }
    }

    var fragments = splitUint8Array(ur, fragmentLength);
    var result = [];

    if (fragments.length == 1) {
        const word = toHexString(ur);
        const crcAppendedWord = word + crc32(ur).toString(16).padStart(8, '0');
        const crcWordBuff = fromHexString(crcAppendedWord);
        const body = crcWordBuff.reduce((result, w) => result + getMinimalWord(w), '');
        result.push("ur:" + type + "/" + body);
    } else {
        while (seqNum < fragments.length) {
            var fragment = fragments[seqNum];
            const seq = (seqNum + 1) + "-" + fragments.length;

            if (fragment.length < fragmentLength) {
                fragment = growUint8Array(fragment, fragmentLength - fragment.length);
            }

            const nestedFragment = [
                seqNum + 1,
                fragments.length,
                ur.length,
                crc32(ur),
                fragment
            ];

            var outerFragment = cbor_encode_array(nestedFragment);

            const word = toHexString(outerFragment);
            const crcAppendedWord = word + crc32(outerFragment).toString(16).padStart(8, '0');
            const crcWordBuff = fromHexString(crcAppendedWord);
            const body = crcWordBuff.reduce((result, w) => result + getMinimalWord(w), '');
            result.push("ur:" + type + "/" + seq + "/" + body);

            ++seqNum;
        }
    }

    return result;
}

// Encode `input` as one single-part BC-UR string, whatever its length (used
// for the Oracle QR, which the Jade expects as a single QR code).
function bcur_encode_single(type, input) {
    var ur = cbor_encode_object(input);

    const word = toHexString(ur);
    const crcAppendedWord = word + crc32(ur).toString(16).padStart(8, '0');
    const crcWordBuff = fromHexString(crcAppendedWord);
    const body = crcWordBuff.reduce((result, w) => result + getMinimalWord(w), '');

    return "ur:" + type + "/" + body;
}

// Decode a minimal-bytewords string and verify its trailing 4-byte CRC32
// (mirrors the encoder, which appends crc32 over the payload big-endian).
// Throws on invalid words or CRC mismatch so a mis-scan is rejected
// instead of silently producing a corrupt request.
function decode_bytewords_checked(bytewords) {
    if (bytewords.length % 2 != 0 || bytewords.length < 10) {
        throw new Error("bytewords length invalid");
    }

    let decodedAll = new Uint8Array(bytewords.length / 2);

    for (let i = 0; i < decodedAll.length; ++i) {
        let value = decodeWord(bytewords[i * 2] + bytewords[i * 2 + 1]);

        if (value === undefined) {
            throw new Error("invalid byteword");
        }

        decodedAll[i] = value;
    }

    let payload = decodedAll.subarray(0, decodedAll.length - 4);
    let crcReader = new BufferReader(decodedAll.subarray(decodedAll.length - 4));

    if (crc32(payload) !== crcReader.readUint32()) {
        throw new Error("bytewords crc mismatch");
    }

    return payload;
}

// Decode the scanned QR payloads of one BC-UR message of the given type.
// `input` is an array holding either the single payload or all numbered
// fragments in order. Throws if the type, a checksum or a word is wrong.
function bcur_decode_object(type, input) {
    var result = {};

    const input0_split = input[0].split('/');

    if (input0_split[0].toLowerCase() !== "ur:" + type) {
        throw new Error("bcur has to start with ur:" + type);
    }

    var ur;

    if (input0_split.length == 3) {
        const seq_split = input0_split[1].split('-');
        const numberOfFrags = parseInt(seq_split[1]);
        var fragments = null;
        var messageCrc = null;

        for (let i = 0; i < numberOfFrags; ++i) {
            let decodedBytes = decode_bytewords_checked(input[i].split('/')[2]);

            let reader = new BufferReader(decodedBytes);
            const nestedFragment = cbor_decode(reader);

            if (fragments == null) {
                fragments = Array(nestedFragment[1]);
            }

            messageCrc = nestedFragment[3];

            if (i == (numberOfFrags - 1)) {
                let urLength = nestedFragment[2];
                let fragmentLength = nestedFragment[4].length;
                let actualFragmentLength = urLength - fragmentLength * (numberOfFrags - 1);
                fragments[i] = nestedFragment[4].subarray(0, actualFragmentLength);
            } else {
                fragments[i] = nestedFragment[4];
            }
        }

        ur = Uint8Array.from(
            fragments.reduce((acc, curr) => [...acc, ...curr], [])
        );

        if (messageCrc !== null && crc32(ur) !== messageCrc) {
            throw new Error("message crc mismatch");
        }
    } else if (input0_split.length == 2) {
        ur = decode_bytewords_checked(input0_split[1]);
    }

    let reader = new BufferReader(ur);
    return cbor_decode(reader);
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        BufferReader, BufferWriter,
        cbor_encode_object, cbor_decode,
        crc32, getMinimalWord, decodeWord, decode_bytewords_checked,
        fromHexString, toHexString,
        bcur_encode_fragments, bcur_encode_single, bcur_decode_object
    };
}
