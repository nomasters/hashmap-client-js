"use strict";
exports.__esModule = true;
var nacl = require("tweetnacl");
var rp = require("request-promise");
var BigInt = require("big-integer");
var hrtime = require("browser-process-hrtime");
exports.maxMessageBytes = 512;
exports.defaultSigMethod = 'nacl-sign-ed25519';
exports.dataTTLDefault = 86400; // 1 day in seconds
exports.dataTTLMax = 604800; // 1 week in seconds
exports.version = '0.0.1';
// unixNanoNow is the equivelant of the go time.Now().UnixNano()
// this function was modified from the one in `nano-time` but
// all values are scoped inside the function and this returns
// a native JS Number type instead of a string like in `nano-time`
function unixNanoNow() {
    var n = hrtime();
    var m = new Date().getTime();
    var d = hrtime(n);
    return BigInt(m).times(1e6).add(BigInt(d[0]).times(1e9).plus(d[1])).valueOf();
}
exports.unixNanoNow = unixNanoNow;
// genNaClSignPrivKey generates a new ed25519 private key and returns
// it as a base64 encoded string
function genNaClSignPrivKey() {
    var keypair = nacl.sign.keyPair();
    return Buffer.from(keypair.secretKey).toString('base64');
}
exports.genNaClSignPrivKey = genNaClSignPrivKey;
// Payload is the primary class used by the hashmap client. It contains
// methods for getting, posting, validating, and analyzing hashmap payloads
var Payload = /** @class */ (function () {
    // the constructor takes an optional uri and endpoint to be used
    // by get and post methods
    function Payload(opts) {
        if (opts && opts.uri)
            this.uri = opts.uri;
        if (opts && opts.endpoint)
            this.endpoint = opts.endpoint;
    }
    // generate takes a base64 encoded key, a message string, and opts object
    // and creates a properly formatted and signed payload
    // it returns a JSON encoded string and sets the class
    // internal state for use with other methods
    Payload.prototype.generate = function (key, message, opts) {
        if (message === void 0) { message = ' '; }
        var ttl = exports.dataTTLDefault;
        if (opts && opts.ttl) {
            ttl = opts.ttl;
        }
        if (ttl > exports.dataTTLMax) {
            throw "invalide ttl, exceeds max";
        }
        var data = {
            message: Buffer.from(message, 'ascii').toString('base64'),
            timestamp: unixNanoNow(),
            sigMethod: exports.defaultSigMethod,
            version: exports.version,
            ttl: ttl
        };
        // dataBytes takes a byte buffer of the data object that has been stringified
        var dataBytes = Buffer.from(JSON.stringify(data), 'ascii');
        var privKey = Buffer.from(key, 'base64');
        var pubKey = privKey.slice(32, 64);
        var signedMessage = nacl.sign(dataBytes, privKey);
        var sig = Buffer.from(signedMessage.slice(0, 64));
        var p = {
            data: dataBytes.toString('base64'),
            pubkey: pubKey.toString('base64'),
            sig: sig.toString('base64')
        };
        this.validate(p);
        return JSON.stringify(p);
    };
    // get takes an endpoint and uri string and sends a get request
    // to a hashmap uri and validates the payload. It returns a promise
    // that resolves to a json formatted response
    Payload.prototype.get = function (endpoint, uri) {
        var _this = this;
        if (!endpoint && !this.endpoint) {
            throw "missing endpoint";
        }
        if (endpoint)
            this.endpoint = endpoint;
        if (!uri && !this.uri) {
            throw "missing uri";
        }
        if (uri)
            this.uri = uri;
        var opts = {
            uri: this.uri + '/' + this.endpoint,
            json: true
        };
        return rp(opts)
            .then(function (resp) {
            _this.validate(resp);
            return resp;
        })["catch"](function (err) { throw err; });
    };
    // post takes a uri and posts the raw payload data to a hashmap server.
    // It returns a promise the resolves to the json body of the endpoint updated
    Payload.prototype.post = function (uri) {
        if (!uri && !this.uri) {
            throw "missing uri";
        }
        if (!this.raw) {
            throw "missing payload";
        }
        if (uri)
            this.uri = uri;
        var opts = {
            uri: this.uri,
            method: 'POST',
            body: this.raw,
            json: true
        };
        return rp(opts);
    };
    // import takes a raw JSON string of a payload, and validates the payload
    Payload.prototype["import"] = function (rawjson) { this.validate(JSON.parse(rawjson)); };
    // validate takes a payloadObject sets and validates a series of checks
    // proper including base64 encoding of values, message requirements, and
    // ensures that the signature is valid based on the message and pubkey
    Payload.prototype.validate = function (p, opts) {
        if (opts === void 0) { opts = {}; }
        this.raw = p;
        this.getDataBytes();
        this.getSigBytes();
        this.getPubkeyBytes();
        this.validateMessage();
        this.validateSig();
    };
    // validateMessage checks that the length of bytes doesn't exceed the
    // allowable maximum.
    Payload.prototype.validateMessage = function () {
        if (this.getMessageBytes().length > exports.maxMessageBytes) {
            throw "message length exceeds max threshold";
        }
    };
    // validateSig concats the sigBytes and the dataBytes and runs the 
    // nacl.sign.open method to ensure the validation of the data is in place
    Payload.prototype.validateSig = function () {
        var sd = Buffer.concat([this.getSigBytes(), this.getDataBytes()]);
        if (!nacl.sign.open(sd, this.getPubkeyBytes())) {
            throw "signature validation failed";
        }
    };
    // getPubkeyBytes returns a bytes buffer for payload pubkey
    Payload.prototype.getPubkeyBytes = function () {
        return Buffer.from(this.raw.pubkey, 'base64');
    };
    // getSigBytes returns a bytes buffer for payload sig
    Payload.prototype.getSigBytes = function () {
        return Buffer.from(this.raw.sig, 'base64');
    };
    // getDataBytes returns a bytes buffer for payload data
    Payload.prototype.getDataBytes = function () {
        return Buffer.from(this.raw.data, 'base64');
    };
    // getData returns the payload data as an object
    Payload.prototype.getData = function () {
        return JSON.parse(this.getDataBytes().toString('ascii'));
    };
    // getMessageBytes returns a bytes buffer for Payload.Data.Message
    Payload.prototype.getMessageBytes = function () {
        return Buffer.from(this.getData().message, 'base64');
    };
    // getMessage returns the Payload.Data.Message as a string
    Payload.prototype.getMessage = function () {
        return this.getMessageBytes().toString('ascii');
    };
    return Payload;
}());
exports.Payload = Payload;
