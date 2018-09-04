const hashmap = require('../dist/index.js');

// This code expects a base64 encoded ed25519 private key to 
// be passed in as an arg.
// var args = process.argv.slice(2);
// var key = args[0]

var opts1 = {
    uri: "https://prototype.hashmap.sh",
    endpoint: "2DrjgbEoLCSYbfMBLJhQnatJP9TUKBGRumksAD1g5noGBMD5sk",
}

console.log("ierNf204JhCfuG7cAztAuC2EEw70X9atTGMmdGM9rgE=")


let key = 'xUCiZL1bBx4HfSWohe4m9PaSHcWQ7c7dIEiluQHxw25IPcCO1GNWONn4I+M9DgbWl81ETgGsD+itIMKeTyLXeg=='

// post payload example
var opts2 = { uri: "https://prototype.hashmap.sh" }
p2 = new hashmap.Payload(opts2)
p2.generate(key, "hello, world it is: " + hashmap.unixNanoNow())
p2.post()
.then(resp => console.log(resp))
.catch(err => console.log(err))


// get payload example
p1 = new hashmap.Payload(opts1)
p1.get()
.then(payload => console.log(p1.getMessage()))
.catch(err => console.log(err))
