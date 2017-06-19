var Crypto = require("nativescript-crypto").NSCrypto;
var crypto = new NSCrypto();

describe("greet function", function() {
    it("exists", function() {
        expect(crypto.hash).toBeDefined();
    });

    // it("returns a string", function() {
    //     expect(crypto.greet()).toEqual("Hello, NS");
    // });
});
