/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/aes-kw", function() {
  var vectors = [
    {
      alg: "A128KW",
      desc: "RFC3339 § 4.1 [Wrap 128 bits of Key Data with a 128-bit KEK]",
      key: "000102030405060708090A0B0C0D0E0F",
      plaintext: "00112233445566778899AABBCCDDEEFF",
      ciphertext: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
    },
    {
      alg: "A256KW",
      desc: "RFC3339 § 4.3 [Wrap 128 bits of Key Data with a 256-bit KEK]",
      key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
      plaintext: "00112233445566778899AABBCCDDEEFF",
      ciphertext: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
    },
    {
      alg: "A256KW",
      desc: "RFC3339 § 4.3 [Wrap 192 bits of Key Data with a 256-bit KEK]",
      key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
      plaintext: "00112233445566778899AABBCCDDEEFF0001020304050607",
      ciphertext: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
    },
    {
      alg: "A256KW",
      desc: "RFC3339 § 4.6 [Wrap 256 bits of Key Data with a 256-bit KEK]",
      key: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
      plaintext: "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
      ciphertext: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
    }
  ];

  vectors.forEach(function(v) {
    var encrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex");

      var promise = algorithms.encrypt(v.alg, key, pdata);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), cdata.toString("hex"));
      });
      return promise;
    };
    var decrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex");

      var promise = algorithms.decrypt(v.alg, key, cdata);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), pdata.toString("hex"));
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") encryption", encrunner);
    it("performs " + v.alg + " (" + v.desc + ") decryption", decrunner);
  });
});
