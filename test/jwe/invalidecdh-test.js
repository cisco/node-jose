/*!
 *
 * Copyright (c) 2017 Cisco Systems, Inc. See LICENSE file.
 */

"use strict";

var forEach = require("lodash/forEach")
var chai = require("chai");

var JWE = require("../../lib/jwe"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/ecdhinvalid", function() {
  var vectors = [
    {
      desc: "ECDH-ES+A128KW + A128CBC-HS256",
      jwk: {
        "kty": "EC",
        "kid": "3f7b122d-e9d2-4ff7-bdeb-a1487063d799",
        "crv": "P-256",
        "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
        "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        "d": "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
      },
      alg: "ECDH-ES+A128KW",
      enc: "A128CBC-HS256",
      plaintext: Buffer.from("Gambling is illegal at Bushwood sir, and I never slice.", "utf8")
    }
  ];
  forEach(vectors, function(v) {
    it("test invalid key for " + v.desc, function() {
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

        //The malicious JWE contains a public key with order 113
        var maliciousJWE1 = {};
        maliciousJWE1.protected  = "eyJhbGciOiJFQ0RILUVTK0ExMjhLVyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiZ1RsaTY1ZVRRN3otQmgxNDdmZjhLM203azJVaURpRzJMcFlrV0FhRkpDYyIsInkiOiJjTEFuakthNGJ6akQ3REpWUHdhOUVQclJ6TUc3ck9OZ3NpVUQta2YzMEZzIiwiY3J2IjoiUC0yNTYifX0";
        maliciousJWE1.encrypted_key = "qGAdxtEnrV_3zbIxU2ZKrMWcejNltjA_dtefBFnRh9A2z9cNIqYRWg";
        maliciousJWE1.iv = "pEA5kX304PMCOmFSKX_cEg";
        maliciousJWE1.ciphertext = "a9fwUrx2JXi1OnWEMOmZhXd94-bEGCH9xxRwqcGuG2AMo-AwHoljdsH5C_kcTqlXS5p51OB1tvgQcMwB5rpTxg";
        maliciousJWE1.tag = "72CHiYFecyDvuUa43KKT6w";

        assert.ok(result);
        var jwe = JWE.createDecrypt(key);
        //this proof that jwk.d (the private key) is equals 26 % 113
        //THIS CAN BE DOIN MANY TIME
        //....
        //AND THAN CHINESE REMAINDER THEOREM FTW
        return jwe.decrypt(maliciousJWE1);
      });
      promise = promise.then(function() {
        assert.ok(false, "unexpected success");
      }, function(err) {
        assert.ok(err);
      });
      return promise;
    });
  });
});
