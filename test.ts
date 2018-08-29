import * as hashmap from './index';
import { expect } from 'chai';
import * as nacl from 'tweetnacl';
import 'mocha';

describe('Private Key Creation', () => {
	const key  = hashmap.genNaClSignPrivKey();
	it('should be be the proper length', () => {
    	expect(key.length).to.equal(88);
	});
	it('should be a string', () => {
    	expect(key).to.be.a('string');
	});
	it('should be able to sign and open a message', () => {
	    const privKey = Buffer.from(key, 'base64');
	    const pubKey  = privKey.slice(32, 64);
	    const message = Buffer.from('test message', 'ascii')
	    const signedMessage = nacl.sign(message, privKey)
	    const openedMessage = Buffer.from(nacl.sign.open(signedMessage, pubKey))
    	expect(openedMessage.toString('base64')).to.be.equal(message.toString('base64'));
	});
});

