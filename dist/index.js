"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const nacl = require("tweetnacl");
const rp = require("request-promise");
const BigInt = require("big-integer");
const multihash = require("multihashes");
exports.maxMessageBytes = 512;
exports.defaultSigMethod = 'nacl-sign-ed25519';
exports.dataTTLDefault = 86400;
exports.dataTTLMax = 604800;
exports.version = '0.0.1';
function unixNanoNow() {
    let n = process.hrtime();
    let m = new Date().getTime();
    let d = process.hrtime(n);
    return BigInt(m).times(1e6).add(BigInt(d[0]).times(1e9).plus(d[1])).valueOf();
}
exports.unixNanoNow = unixNanoNow;
function genNaClSignPrivKey() {
    const keypair = nacl.sign.keyPair();
    return Buffer.from(keypair.secretKey).toString('base64');
}
exports.genNaClSignPrivKey = genNaClSignPrivKey;
function getEd25519PubkeyFromPrivateKey(privateKey) {
    const privKey = Buffer.from(privateKey, 'base64');
    return privKey.slice(32, 64).toString('base64');
}
exports.getEd25519PubkeyFromPrivateKey = getEd25519PubkeyFromPrivateKey;
function getBlake2b256MultiHash(publicKey) {
    const pubKey = Buffer.from(publicKey, 'base64');
    return multihash.toB58String(multihash.encode(pubKey, 'blake2b-256'));
}
exports.getBlake2b256MultiHash = getBlake2b256MultiHash;
class Payload {
    constructor(opts) {
        if (opts && opts.uri)
            this.uri = opts.uri;
        if (opts && opts.endpoint)
            this.endpoint = opts.endpoint;
    }
    generate(key, message = ' ', opts) {
        let ttl = exports.dataTTLDefault;
        if (opts && opts.ttl) {
            ttl = opts.ttl;
        }
        if (ttl > exports.dataTTLMax) {
            throw new Error('invalid ttl, exceeds max');
        }
        const data = {
            message: Buffer.from(message, 'ascii').toString('base64'),
            timestamp: unixNanoNow(),
            sigMethod: exports.defaultSigMethod,
            version: exports.version,
            ttl: ttl,
        };
        const dataBytes = Buffer.from(JSON.stringify(data), 'ascii');
        const privKey = Buffer.from(key, 'base64');
        const pubKey = privKey.slice(32, 64);
        const signedMessage = nacl.sign(dataBytes, privKey);
        const sig = Buffer.from(signedMessage.slice(0, 64));
        const p = {
            data: dataBytes.toString('base64'),
            pubkey: pubKey.toString('base64'),
            sig: sig.toString('base64'),
        };
        this.validate(p);
        return JSON.stringify(p);
    }
    get(endpoint, uri) {
        if (!endpoint && !this.endpoint) {
            throw new Error("missing endpoint");
        }
        if (endpoint)
            this.endpoint = endpoint;
        if (!uri && !this.uri) {
            throw new Error("missing uri");
        }
        if (uri)
            this.uri = uri;
        const opts = {
            uri: this.uri + '/' + this.endpoint,
            json: true
        };
        return rp(opts)
            .then(resp => {
            this.validate(resp);
            return resp;
        })
            .catch(err => { throw err; });
    }
    post(uri) {
        if (!uri && !this.uri) {
            throw new Error("missing uri");
        }
        if (!this.raw) {
            throw new Error("missing payload");
        }
        if (uri)
            this.uri = uri;
        const opts = {
            uri: this.uri,
            method: 'POST',
            body: this.raw,
            json: true,
        };
        return rp(opts);
    }
    import(rawjson) { this.validate(JSON.parse(rawjson)); }
    validate(p, opts = {}) {
        this.raw = p;
        this.getDataBytes();
        this.getSigBytes();
        this.getPubkeyBytes();
        this.validateMessage();
        this.validateSig();
    }
    validateMessage() {
        if (this.getMessageBytes().length > exports.maxMessageBytes) {
            throw new Error("message length exceeds max threshold");
        }
    }
    validateSig() {
        const sd = Buffer.concat([this.getSigBytes(), this.getDataBytes()]);
        if (!nacl.sign.open(sd, this.getPubkeyBytes())) {
            throw new Error("signature validation failed");
        }
    }
    getPubkeyBytes() {
        return Buffer.from(this.raw.pubkey, 'base64');
    }
    getSigBytes() {
        return Buffer.from(this.raw.sig, 'base64');
    }
    getDataBytes() {
        return Buffer.from(this.raw.data, 'base64');
    }
    getData() {
        return JSON.parse(this.getDataBytes().toString('ascii'));
    }
    getMessageBytes() {
        return Buffer.from(this.getData().message, 'base64');
    }
    getMessage() {
        return this.getMessageBytes().toString('ascii');
    }
}
exports.Payload = Payload;
