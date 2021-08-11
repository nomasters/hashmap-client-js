import * as hashmap from './dist/index';
import * as nacl from 'tweetnacl';
import * as multihash from 'multihashes';
import * as blake from 'blakejs';
import * as nock from 'nock';
import * as chai from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import 'mocha';

chai.use(chaiAsPromised);
const expect = chai.expect;

describe('Constants', () => {
    const testTable = [
        ['maxMessageBytes', hashmap.maxMessageBytes, 512],
        ['defaultSigMethod', hashmap.defaultSigMethod, 'nacl-sign-ed25519'],
        ['dataTTLDefault', hashmap.dataTTLDefault, 86400],
        ['dataTTLMax', hashmap.dataTTLMax, 604800],
        ['version', hashmap.version, '0.0.1'],
    ]
    for (let i = 0; i < testTable.length; i++) {
        let t = testTable[i]
        it(`should match ${t[0]} to ${t[2]}`, () => {
            expect(t[1]).to.equal(t[2]);
        });
    }
});

describe('Private Key Generator', () => {
    const key = hashmap.genNaClSignPrivKey();
    it('should be be the proper length', () => {
        expect(key.length).to.equal(88);
    });
    it('should be a string', () => {
        expect(key).to.be.a('string');
    });
    it('should be able to sign and open a message', () => {
        const privKey = Buffer.from(key, 'base64');
        const pubKey = privKey.slice(32, 64);
        const message = Buffer.from('test message', 'ascii')
        const signedMessage = nacl.sign(message, privKey)
        const openedMessage = Buffer.from(nacl.sign.open(signedMessage, pubKey))
        expect(openedMessage.toString('base64')).to.equal(message.toString('base64'));
    });
});

describe('Public Key', () => {
    const key = hashmap.genNaClSignPrivKey();
    it('should valid base64 string from private key', () => {
        const privKey = Buffer.from(key, 'base64');
        const pubKey = privKey.slice(32, 64).toString('base64');
        const pk = hashmap.getEd25519PubkeyFromPrivateKey(key);
        expect(pk).to.be.equal(pubKey);
    });
    it('should be able to encode and decode from multihash', () => {
        const pk = hashmap.getEd25519PubkeyFromPrivateKey(key);
        const pkHash = hashmap.getBlake2b256MultiHash(pk)
        const multih = multihash.fromB58String(pkHash)
        const mh = multihash.decode(multih)
        const hash = Buffer.from(blake.blake2b(Buffer.from(pk, 'base64'), null, 32)).toString('base64')

        expect(Buffer.from(mh.digest.buffer).toString('base64')).to.equal(hash)
    });
});

describe('Unix Nano Time Stamp Generator', () => {
    it('should be a number', () => {
        const timestamp = hashmap.unixNanoNow();
        expect(timestamp).to.be.a('number');
    });
    it('should be accurate to at least Date.now() (1/1000 of a second)', () => {
        const timestamp = Math.floor(hashmap.unixNanoNow() / 10000000);
        const unixTime = Math.floor(Date.now() / 10);
        expect(timestamp).to.equal(unixTime);
    });
});

describe('ServerURI', () => {
    it('should work with setter and getter functions', () => {
        const uri = 'https://prototype.hashmap.sh'
        hashmap.setServerURI(uri)
        expect(hashmap.getSeverURI()).to.equal(uri)
        hashmap.setServerURI('')
    });
})

describe('Payload', () => {
    const defaultPrivKey = hashmap.genNaClSignPrivKey();
    const defaultPubkey = hashmap.getEd25519PubkeyFromPrivateKey(defaultPrivKey);
    const uri = 'https://prototype.hashmap.sh'
    const endpoint = hashmap.getBlake2b256MultiHash(defaultPubkey)
    const defaultMessage = 'test'

    it('should initialize without uri options', () => {
        let p = new hashmap.Payload()
        expect(p.uri).to.be.undefined
    });
    it('should initialize with serverURI', () => {
        hashmap.setServerURI(uri)
        let p = new hashmap.Payload()
        hashmap.setServerURI('')
        expect(p.uri).to.equal(uri)
    });
    it('should initialize without endpoint options', () => {
        let p = new hashmap.Payload()
        expect(p.endpoint).to.be.undefined
    });
    it('should initialize with uri options', () => {
        let opts = { uri: uri, endpoint: endpoint }
        let p = new hashmap.Payload(opts)
        expect(p.uri).to.equal(opts.uri)
    });
    it('should initialize with endpoint options', () => {
        let opts = { uri: uri, endpoint: endpoint }
        let p = new hashmap.Payload(opts)
        expect(p.endpoint).to.equal(opts.endpoint)
    });
    it('should generate a signed payload', () => {
        let p = new hashmap.Payload()
        p.generate(defaultPrivKey, defaultMessage)
        expect(p.raw.pubkey).to.be.a('string')
    });
    it('should generate a signed payload with a custom ttl', () => {
        let p = new hashmap.Payload()
        p.generate(defaultPrivKey, defaultMessage, { ttl: 5 })
        expect(p.raw.pubkey).to.be.a('string')
    });
    it('should generate a signed payload with null message', () => {
        let p = new hashmap.Payload()
        p.generate(defaultPrivKey)
        expect(p.raw.pubkey).to.be.a('string')
    });
    it('should reject a signed payload attempt with ttl greater than max', () => {
        let p = new hashmap.Payload()
        let opts = { ttl: hashmap.dataTTLMax + 1 }
        expect(() => p.generate(defaultPrivKey, defaultMessage, opts)).to.throw()
    });
    it('should reject a signed payload attempt when the message is too large', () => {
        let p = new hashmap.Payload()
        let message = `fdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
        deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`
        expect(() => p.generate(defaultPrivKey, message)).to.throw()
    });
    it('should import a properly formatted json payload', () => {
        let p = new hashmap.Payload()
        let jsonPayload = p.generate(defaultPrivKey, defaultMessage, 'test')
        let p2 = new hashmap.Payload()
        p2.import(jsonPayload)
        expect(p2.getMessage()).to.equal(defaultMessage)
    });
    it('should reject an improperly formatted json payload', () => {
        let jsonPayload = `{"total":"fail"}`
        let p = new hashmap.Payload()
        expect(() => p.import(jsonPayload)).to.throw()
    });
    it('should get a payload from a hashmap server', () => {
        let g = new hashmap.Payload()
        let body = g.generate(defaultPrivKey, defaultMessage)

        nock(uri)
            .get('/' + hashmap.getBlake2b256MultiHash(defaultPubkey))
            .reply(200, body);

        let opts = {
            uri: uri,
            endpoint: hashmap.getBlake2b256MultiHash(defaultPubkey),
        }
        let p = new hashmap.Payload(opts)
        return expect(p.get()).to.eventually.be.fulfilled;
    });
    it('should get a payload to a hashmap serve with endpoint and uri passed to the method', () => {
        let g = new hashmap.Payload()
        let body = g.generate(defaultPrivKey, defaultMessage)

        nock(uri)
            .get('/' + hashmap.getBlake2b256MultiHash(defaultPubkey))
            .reply(200, body);

        let p = new hashmap.Payload()
        return expect(p.get(endpoint, uri)).to.eventually.be.fulfilled;
    });

    it('should reject a get request without an endpoint', () => {
        let opts = { uri: uri }
        let p = new hashmap.Payload(opts)
        return expect(p.get()).to.eventually.be.rejected;
    });
    it('should reject a get request without a uri', () => {
        let opts = { endpoint: endpoint }
        let p = new hashmap.Payload(opts)
        return expect(p.get()).to.eventually.be.rejected;
    });
    it('should reject a get request from an endpoint to pubkey mismatch', () => {
        const badKey = hashmap.genNaClSignPrivKey();

        let g = new hashmap.Payload()
        let body = g.generate(badKey, defaultMessage)

        nock(uri)
            .get('/' + hashmap.getBlake2b256MultiHash(defaultPubkey))
            .reply(200, body);

        let opts = {
            uri: uri,
            endpoint: hashmap.getBlake2b256MultiHash(defaultPubkey),
        }
        let p = new hashmap.Payload(opts)
        return expect(p.get()).to.eventually.be.rejected;
    });

    it('should post a payload to a hashmap server', () => {
        nock(uri)
            .post('/')
            .reply(200, { endpoint: hashmap.getBlake2b256MultiHash(defaultPubkey) });

        let opts = { uri: uri }
        let p = new hashmap.Payload(opts)
        p.generate(defaultPrivKey, defaultMessage)
        return expect(p.post()).to.eventually.be.fulfilled;
    });
    it('should post a payload to a hashmap serve with uri passed to post method', () => {
        nock(uri)
            .post('/')
            .reply(200, { endpoint: hashmap.getBlake2b256MultiHash(defaultPubkey) });
        let p = new hashmap.Payload()
        p.generate(defaultPrivKey, defaultMessage)
        return expect(p.post(uri)).to.eventually.be.fulfilled;
    });
    it('should reject a post request without a raw payload', () => {
        let p = new hashmap.Payload()
        return expect(p.post(uri)).to.eventually.be.rejected;
    });
    it('should reject a post request without a uri', () => {
        let p = new hashmap.Payload()
        return expect(p.post()).to.eventually.be.rejected;
    });

    it('should reject an invalid signature', () => {
        let p = new hashmap.Payload()
        p.generate(defaultPrivKey, defaultMessage)
        p.raw.sig = 'fail' + p.raw.sig
        expect(() => p.validateSig()).to.throw()
    });
});