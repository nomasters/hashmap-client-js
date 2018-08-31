# hashmap-client
a javascript client library for interacting with [hashmap](https://github.com/nomasters/hashmap) server and payloads.

[![CircleCI][1]][2] [![Known Vulnerabilities][3]][4] [![Coverage Status][5]][6] [![npm version][7]][8]

[1]: https://circleci.com/gh/nomasters/hashmap-client-js.svg?style=svg
[2]: https://circleci.com/gh/nomasters/hashmap-client-js
[3]: https://snyk.io/test/github/nomasters/hashmap-client-js/badge.svg
[4]: https://snyk.io/test/github/nomasters/hashmap-client-js
[5]: https://coveralls.io/repos/github/nomasters/hashmap-client-js/badge.svg?branch=master
[6]: https://coveralls.io/github/nomasters/hashmap-client-js?branch=master
[7]: https://img.shields.io/npm/v/hashmap-client.svg
[8]: https://www.npmjs.com/package/hashmap-client

## Summary

This is a simple client for generating, interacting with, submitting, and fetching hashmap payloads. If you are new to `hashmap`, you can read more about [it in its github page](https://github.com/nomasters/hashmap).

NOTE: `hashmap` is in early alpha. It has not been properly reviewed for security and privacy leaks and should only be used for experimental purposes. Large and small breaking changes may be introduces while in early alpha.

Install Instructions

```
npm install hashmap-client
```

The purpose of this library is to make interacting with hashmap payloads easy and predictable. Under the hood, this library runs through a series of validity checks on the signature, endpoint to public key verification, and formatting requirements.

### Initializing a payload

To interact with a payload, initiate a new instance of a payload.

```
let payload = new hashmap.Payload();
```

You can set a global default `ServerURI` with the `setServerURI(uri)` function

```
hashmap.setServerURI('https://prototype.hashmap.sh')
```

You can optionally initialize a payload with the `uri` and `endpoint` for a hashmap key-value store on initialization of a new instance of payload. Passing in a uri for a payload overrides the global default for this specific instance.

```
let opts = {
    uri: "https://prototype.hashmap.sh",
    endpoint: "2DrjgbD6zUx2svjd4NcXfsTwykspqEQmcC2WC7xeBUyPcBofuo",
}
let payload = new hashmap.Payload(opts);
```

### Getting a payload from a hashmap server

To get a hashmap payload from a specific endpoint, either initialize a payload with the `uri` and `endpoint` as outlined above, or pass them in as arguments in the `.get()` method.

The `get()` method returns a promise that resolves to a payload object or an error.


```
let endpoint = '2DrjgbD6zUx2svjd4NcXfsTwykspqEQmcC2WC7xeBUyPcBofuo';
let payload  = new hashmap.Payload();

payload.get(endpoint)
	.then(resp => console.log(resp))
	.catch(err => console.log(err))
```

### Generating and Posting a payload to a hashmap server

To post a payload, you will need:

- the `uri` for the hashmap server
- a base64 encoded `ed25519` private key (for signing the payload)
- a string formatted message to include in the payload (no larger than 512 bytes)

The generator takes care of the rest. 

`hashmap-client` also includes an `ed25519` private key generator that returns the properly formatted base64 string


```
// Generate a Private Key (don't share this)
let key = hashmap.genNaClSignPrivKey();
let message = 'hello, world';

// add uri to options
let opts = { uri: "https://prototype.hashmap.sh" }

// initialize Payload with options
let payload = new hashmap.Payload(opts)

// generate the signed hashmap payload
payload.generate(key, message)

payload.post()
.then(resp => console.log(resp))
.catch(err => console.log(err))

```

NOTE: Post the payload as soon as possible after generating it. Hashmap server checks the signed timestamp included with the payload and rejects payloads outside of a timestamp drift threshold.

