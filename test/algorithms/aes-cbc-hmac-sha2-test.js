/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/aes-cbc-hmac-sha2", function() {
  var vectors = [
    {
      alg: "A128CBC-HS256",
      desc: "RFC 7518 Appendix B.1. Test Cases for AEAD_AES_128_CBC_HMAC_SHA256",
      key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      iv: "1af38c2dc2b96ffdd86694092341bc04",
      plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
      ciphertext: "c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db",
      aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
      tag: "652c3fa36b0a7c5b3219fab3a30bc1c4"
    },
    {
      alg: "A256CBC-HS512",
      desc: "RFC 7518 Appendix B.3. Test Cases for AEAD_AES_256_CBC_HMAC_SHA512",
      key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      iv: "1af38c2dc2b96ffdd86694092341bc04",
      plaintext: "41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365",
      ciphertext: "4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950bbe2638d09dd7a4930930806d0703b1f6",
      aad: "546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673",
      tag: "4dd3b4c088a7f45c216839645b2012bf2e6269a8c56a816dbc1b267761955bc5"
    }
  ];
  vectors.forEach(function(v) {
    var encrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex"),
          mac = Buffer.from(v.tag, "hex"),
          props = {
            iv: Buffer.from(v.iv, "hex"),
            aad: Buffer.from(v.aad, "hex")
          };

      var promise = algorithms.encrypt(v.alg, key, pdata, props);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), cdata.toString("hex"));
        assert.equal(result.tag.toString("hex"), mac.toString("hex"));
      });
      return promise;
    };
    var decrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex"),
          props = {
            iv: Buffer.from(v.iv, "hex"),
            aad: Buffer.from(v.aad, "hex"),
            tag: Buffer.from(v.tag, "hex")
          };

      var promise = algorithms.decrypt(v.alg, key, cdata, props);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), pdata.toString("hex"));
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") encryption", encrunner);
    it("performs " + v.alg + " (" + v.desc + ") decryption", decrunner);

    it('should not pass verification (truncated tag)', function() {
      var tamperedTag = v.tag.substring(0, 6);
      var key = Buffer.from(v.key, "hex"),
      cdata = Buffer.from(v.ciphertext, "hex"),
      props = {
        iv: Buffer.from(v.iv, "hex"),
        aad: Buffer.from(v.aad, "hex"),
        tag: Buffer.from(tamperedTag, "hex")
      };
      var promise = algorithms.decrypt(v.alg, key, cdata, props);
      promise = promise.then(function() {
        assert(false, "unexpected success");
      });
      promise = promise.catch(function(err) {
        assert(err);
      });
      return promise;
    })
    it('should not pass verification, (empty tag)', function() {
      var tamperedTag = "";
      var key = Buffer.from(v.key, "hex"),
      cdata = Buffer.from(v.ciphertext, "hex"),
      props = {
        iv: Buffer.from(v.iv, "hex"),
        aad: Buffer.from(v.aad, "hex"),
        tag: Buffer.from(tamperedTag, "hex")
      };
      var promise = algorithms.decrypt(v.alg, key, cdata, props);
      promise = promise.then(function() {
        assert(false, "unexpected success");
      });
      promise = promise.catch(function(err) {
        assert(err);
      });
      return promise;
    });
  });
});
