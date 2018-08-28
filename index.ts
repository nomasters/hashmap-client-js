import * as nacl from 'tweetnacl';
import * as rp from "request-promise";
import * as BigInt from 'big-integer';

export const maxMessageBytes: number  = 512
export const defaultSigMethod: string = 'nacl-sign-ed25519'
export const dataTTLDefault: number   = 86400  // 1 day in seconds
export const dataTTLMax: number       = 604800 // 1 week in seconds
export const version: string          = '0.0.1'


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

export interface PayloadOptions {
    uri: string
    endpoint: string
}

export interface GenerateOptions {
    ttl: number
}

export interface PayloadObject {
    data: string
    sig: string
    pubkey: string
}

export class Payload {
    public uri: string
    public endpoint: string
    public raw: PayloadObject

    constructor(opts? : PayloadOptions) {
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
            throw "invalide ttl, exceeds max"
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
    public get(endpoint?: string, uri?: string) {
        if (!endpoint && !this.endpoint) { throw "missing endpoint" }
        if (endpoint) this.endpoint = endpoint
        if (!uri && !this.uri) { throw "missing uri" }
        if (uri) this.uri = uri
        const opts = {
            uri: this.uri + '/' + this.endpoint,
            json: true
        }
        return rp(opts)
        .then(resp => {
            this.validate(resp)
            return resp
        })
        .catch(err => { throw err })
    }
    public post(uri?: string) {
        if (!uri && !this.uri) { throw "missing uri" }
        if (!this.raw) { throw "missing payload" }
        if (uri) this.uri = uri
        const opts = {
            uri: this.uri,
            method: 'POST',
            body: this.raw,
            json: true,
        }
        return rp(opts)
    }
    public import(rawjson: string) { this.validate(JSON.parse(rawjson)) }
    public validate(p: PayloadObject, opts={}) {
        this.raw     = p
        this.getDataBytes()
        this.getSigBytes()
        this.getPubkeyBytes()
        this.validateMessage()
        this.validateSig()
    }
    public validateMessage() {
        if (this.getMessageBytes().length > maxMessageBytes) { 
            throw "message length exceeds max threshold" 
        }
    }
    public validateSig() {
        const sd = Buffer.concat([this.getSigBytes(), this.getDataBytes()])
        if (!nacl.sign.open(sd, this.getPubkeyBytes())) { 
            throw "signature validation failed" 
        }
    }
    public getPubkeyBytes() {
        return Buffer.from(this.raw.pubkey, 'base64');
    }
    public getSigBytes() {
        return Buffer.from(this.raw.sig, 'base64');
    }
    public getDataBytes() {
        return Buffer.from(this.raw.data, 'base64');
    }
    public getData() { 
        return JSON.parse(this.getDataBytes().toString('ascii')) 
    }
    public getMessageBytes() { 
        return Buffer.from(this.getData().message, 'base64') 
    }
    public getMessage() { 
        return this.getMessageBytes().toString('ascii') 
    }
}