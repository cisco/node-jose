"use strict";

var chai = require("chai");

var JWE = require("../../lib/jwe"),
  JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/allowedalgs", function() {
  var a256kw = {
    key: {
      "kty": "oct",
      "kid": "lkSOb9wLb8VTKr0Z1TMqQoa_oSoNNn8uukn6taSuwS0",
      "k": "o9oXnnQleK4oDDN1AngQ610cn39o6Y8KPirzITJRfWw",
      "alg": "A256KW"
    },
    fields: {
      enc: "A256GCM"
    },
    plaintext: "this is not good content"
  };
  var a256gcm = {
    key: {
      "kty": "oct",
      "kid": "V5O0olRc1BSdaubnd_REP2B0xBjo8gBmNcLlv_F8hk0",
      "k": "wB_gTgRKTtYSk-ul_W-96WU92evFr01tPN6WE8A8BEU",
      "alg": "A256GCM"
    },
    plaintext: "this is very good content"
  };

  function decryptAllowed(vector, opts) {
    var p;
    p = JWE.createDecrypt(vector.key, opts).
      decrypt(vector.encrypted);
    p = p.then(function (result) {
      assert.strictEqual(result.payload.toString("utf8"), vector.plaintext);
    });
    return p;
  }

  before(function() {
    var pending = [a256gcm, a256kw].map(function(vector) {
      var p = JWK.asKey(vector.key);
      p = p.then(function(result) {
        vector.key = result;
        return result;
      });
      p = p.then(function(key) {
        return JWE.createEncrypt({ format: "compact", fields: vector.fields }, key).final(vector.plaintext, "utf8");
      });
      p = p.then(function(result) {
        vector.encrypted = result;
        return result;
      });
      return p;
    });
    return Promise.all(pending);
  });

  it("Default algorithm is preserved", function() {
    var opts = {
      algorithms: ["dir", "A256GCM"]
    };

    var pending = [
      decryptAllowed(a256gcm, opts),
      decryptAllowed(a256kw, {})
    ];
    return Promise.all(pending);
  });
});
