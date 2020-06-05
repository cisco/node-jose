"use strict";

var forEach = require("lodash/forEach")
var chai = require("chai");

var JWE = require("../../lib/jwe"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/roundtrip", function() {
  var vectors = [
    {
      desc: "ECDH-ES + A128CBC-HS256",
      jwk: {
        "kty": "EC",
        "kid": "3f7b122d-e9d2-4ff7-bdeb-a1487063d799",
        "crv": "P-256",
        "x": "Hx02_oMKJnNb1-bgXfzeuBHagkh20muzegMOGEU8G_g",
        "y": "Ez2IYifZI88vRiCpA4Y6W8oMKZOi2nhZStxilPYTDk0",
        "d": "FS9F8-SyMjTZFXwCH7F--D8Qq_GSpG6FBEM-Nb8ily0"
      },
      alg: "ECDH-ES",
      enc: "A128CBC-HS256",
      plaintext: Buffer.from("hello world", "utf8")
    },
    {
      desc: "ECDH-ES+A128KW + A128GCM",
      jwk: {
        "kty": "EC",
        "kid": "3f7b122d-e9d2-4ff7-bdeb-a1487063d799",
        "crv": "P-256",
        "x": "Hx02_oMKJnNb1-bgXfzeuBHagkh20muzegMOGEU8G_g",
        "y": "Ez2IYifZI88vRiCpA4Y6W8oMKZOi2nhZStxilPYTDk0",
        "d": "FS9F8-SyMjTZFXwCH7F--D8Qq_GSpG6FBEM-Nb8ily0"
      },
      alg: "ECDH-ES+A128KW",
      enc: "A128GCM",
      plaintext: Buffer.from("hello world", "utf8")
    }
  ];
  forEach(vectors, function(v) {
    it("test " + v.desc + " encrypt + decrypt", function() {
      var promise,
          key;
      promise = JWK.asKey(v.jwk);
      promise = promise.then(function(jwk) {
        key = jwk;
        var cfg = {
          contentAlg: v.enc
        };
        var recipient = {
          key: key,
          header: {
            alg: v.alg
          }
        };
        var jwe = JWE.createEncrypt(cfg, recipient);
        return jwe.update(v.plaintext).final();
      });
      promise = promise.then(function(result) {
        assert.ok(result);
        var jwe = JWE.createDecrypt(key);
        return jwe.decrypt(result);
      });
      promise = promise.then(function(result) {
        assert.deepEqual(result.plaintext, v.plaintext);
      });
      return promise;
    });
  });
});
