const hashmap = require('./dist/index.js');

// This code expects a base64 encoded ed25519 private key to 
// be passed in as an arg.
var args = process.argv.slice(2);
var key = args[0]

var opts1 = {
    uri: "https://prototype.hashmap.sh",
    endpoint: "2DrjgbD6zUx2svjd4NcXfsTwykspqEQmcC2WC7xeBUyPcBofuo",
}

// get payload example
p1 = new hashmap.Payload(opts1)
p1.get()
.then(payload => console.log(p1.getMessage()))
.catch(err => console.log(err))

// post payload example
var opts2 = { uri: "https://prototype.hashmap.sh" }
p2 = new hashmap.Payload(opts2)
p2.generate(key, "hello, world it is: " + hashmap.unixNanoNow())
p2.post()
.then(resp => console.log(resp))
.catch(err => console.log(err))
