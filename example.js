const hashmap = require('./dist/index.js');

var opts = {
    uri: "https://prototype.hashmap.sh",
    endpoint: "2DrjgbD6zUx2svjd4NcXfsTwykspqEQmcC2WC7xeBUyPcBofuo",
}

var args = process.argv.slice(2);
var key = args[0]

// get payload example
p1 = new hashmap.Payload(opts)
p1.get()
.then(payload => console.log(p1.getMessage()))
.catch(err => console.log(err))

// post payload example
var opts = { uri: "https://prototype.hashmap.sh" }
p2 = new hashmap.Payload(opts)
p2.generate(key, "hello, world it is: " + hashmap.unixNanoNow())
p2.post()
.then(resp => console.log(resp))
.catch(err => console.log(err))
