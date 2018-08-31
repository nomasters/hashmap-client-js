import * as nacl from 'tweetnacl';
import * as rp from "request-promise";
import * as BigInt from 'big-integer';
import * as multihash from 'multihashes';

export const maxMessageBytes: number  = 512
export const defaultSigMethod: string = 'nacl-sign-ed25519'
export const dataTTLDefault: number   = 86400  // 1 day in seconds
export const dataTTLMax: number       = 604800 // 1 week in seconds
export const version: string          = '0.0.1'

// globally scoped variable for uri
var ServerURI: string = ''

// setServerURI sets the private variable ServerURI
export function setServerURI(uri: string) {
    ServerURI = uri
}

// setServerURI gets the private variable ServerURI
export function getSeverURI() {
    return ServerURI
}

// unixNanoNow is the equivelant of the go time.Now().UnixNano()
// this function was modified from the one in `nano-time` but
// all values are scoped inside the function and this returns
// a native JS Number type instead of a string like in `nano-time`
export function unixNanoNow() {
    let n = process.hrtime();
    let m = new Date().getTime();
    let d = process.hrtime(n);
    return BigInt(m).times(1e6).add(BigInt(d[0]).times(1e9).plus(d[1])).valueOf();
}

// genNaClSignPrivKey generates a new ed25519 private key and returns
// it as a base64 encoded string
export function genNaClSignPrivKey() {
    const keypair = nacl.sign.keyPair()
    return Buffer.from(keypair.secretKey).toString('base64')
}

// getEd25519PubkeyFromPrivateKey takes a base64 encoded string of the 
// private key and returns a base64 encoded string of the public key
export function getEd25519PubkeyFromPrivateKey(privateKey: string) {
    const privKey = Buffer.from(privateKey, 'base64');
    return privKey.slice(32,64).toString('base64');
}

// getBlake2b256MultiHash takes a base64 encoded string of the public key
// and returns a base58 encoded multihash in blake2b256 formatting
export function getBlake2b256MultiHash(publicKey: string) {
    const pubKey = Buffer.from(publicKey, 'base64');
    return multihash.toB58String(multihash.encode(pubKey, 'blake2b-256'))
}

// PayloadOptions is the interface used for the Payload Constructor
export interface PayloadOptions {
    uri: string
    endpoint: string
}

// GenerateOptions is the interface used for the generate method
export interface GenerateOptions {
    ttl: number
}

// PayloadObject is the interface description of the JSON Payload
// Parsed into an object
export interface PayloadObject {
    data: string
    sig: string
    pubkey: string
}

// Payload is the primary class used by the hashmap client. It contains
// methods for getting, posting, validating, and analyzing hashmap payloads
export class Payload {
    public uri: string
    public endpoint: string
    public raw: PayloadObject

    // the constructor takes an optional uri and endpoint to be used
    // by get and post methods
    constructor(opts? : PayloadOptions) {
        if (ServerURI !== '') this.uri = ServerURI
        if (opts && opts.uri) this.uri = opts.uri
        if (opts && opts.endpoint) this.endpoint = opts.endpoint
    }

    // generate takes a base64 encoded key, a message string, and opts object
    // and creates a properly formatted and signed payload
    // it returns a JSON encoded string and sets the class
    // internal state for use with other methods
    public generate(key: string, message=' ', opts? : GenerateOptions) {
        let ttl = dataTTLDefault
        if (opts && opts.ttl) {
            ttl = opts.ttl
        }
        if (ttl > dataTTLMax) {
            throw new Error('invalid ttl, exceeds max')
        }
        const data = {
            message: Buffer.from(message, 'ascii').toString('base64'),
            timestamp: unixNanoNow(),
            sigMethod: defaultSigMethod,
            version: version,
            ttl: ttl,
        }
        // dataBytes takes a byte buffer of the data object that has been stringified
        const dataBytes = Buffer.from(JSON.stringify(data), 'ascii')
        const privKey = Buffer.from(key, 'base64');
        const pubKey = privKey.slice(32,64)
        const signedMessage = nacl.sign(dataBytes, privKey)
        const sig = Buffer.from(signedMessage.slice(0,64))

        const p = {
            data: dataBytes.toString('base64'),
            pubkey: pubKey.toString('base64'),
            sig: sig.toString('base64'),
        }
        this.validate(p)
        return JSON.stringify(p)
    }

    // get takes an endpoint and uri string and sends a get request
    // to a hashmap uri and validates the payload. It returns a promise
    // that resolves to a json formatted response
    public get(endpoint?: string, uri?: string) {
        if (!endpoint && !this.endpoint) { 
            return Promise.reject(new Error("missing endpoint")) 
        }
        if (endpoint) this.endpoint = endpoint
        if (!uri && !this.uri) { 
            return Promise.reject(new Error("missing uri")) 
        }
        if (uri) this.uri = uri
        const opts = {
            uri: this.uri + '/' + this.endpoint,
            json: true
        }
        return rp(opts)
            .then(resp => {
                this.validate(resp)
                // TODO check that the ENDPOINT matches the pubkey
                if (this.endpoint !== getBlake2b256MultiHash(this.raw.pubkey)) {
                    throw new Error('endpoint to pubkey mismatch')
                }
                return resp
            })
    }

    // post takes a uri and posts the raw payload data to a hashmap server.
    // It returns a promise the resolves to the json body of the endpoint updated
    public post(uri?: string) {
        if (!uri && !this.uri) { return Promise.reject(new Error("missing uri")) }
        if (!this.raw) { return Promise.reject(new Error("missing payload")) }
        if (uri) this.uri = uri
        const opts = {
            uri: this.uri,
            method: 'POST',
            body: this.raw,
            json: true,
        }
        return rp(opts)
    }

    // import takes a raw JSON string of a payload, and validates the payload
    public import(rawjson: string) { this.validate(JSON.parse(rawjson)) }

    // validate takes a payloadObject sets and validates a series of checks
    // proper including base64 encoding of values, message requirements, and
    // ensures that the signature is valid based on the message and pubkey
    public validate(p: PayloadObject, opts={}) {
        this.raw     = p
        this.getDataBytes()
        this.getSigBytes()
        this.getPubkeyBytes()
        this.validateMessage()
        this.validateSig()
    }

    // validateMessage checks that the length of bytes doesn't exceed the
    // allowable maximum.
    public validateMessage() {
        if (this.getMessageBytes().length > maxMessageBytes) { 
            throw new Error("message length exceeds max threshold")
        }
    }

    // validateSig concats the sigBytes and the dataBytes and runs the 
    // nacl.sign.open method to ensure the validation of the data is in place
    public validateSig() {
        const sd = Buffer.concat([this.getSigBytes(), this.getDataBytes()])
        if (!nacl.sign.open(sd, this.getPubkeyBytes())) { 
            throw new Error("signature validation failed")
        }
    }

    // getPubkeyBytes returns a bytes buffer for payload pubkey
    public getPubkeyBytes() {
        return Buffer.from(this.raw.pubkey, 'base64');
    }

    // getSigBytes returns a bytes buffer for payload sig
    public getSigBytes() {
        return Buffer.from(this.raw.sig, 'base64');
    }

    // getDataBytes returns a bytes buffer for payload data
    public getDataBytes() {
        return Buffer.from(this.raw.data, 'base64');
    }

    // getData returns the payload data as an object
    public getData() { 
        return JSON.parse(this.getDataBytes().toString('ascii')) 
    }

    // getMessageBytes returns a bytes buffer for Payload.Data.Message
    public getMessageBytes() { 
        return Buffer.from(this.getData().message, 'base64') 
    }

    // getMessage returns the Payload.Data.Message as a string
    public getMessage() { 
        return this.getMessageBytes().toString('ascii') 
    }
}