/*!
 *
 * Copyright (c) 2016 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");

var JWK = require("../../lib/jwk");
var JWE = require("../../lib/jwe");
var util = require("../../lib/util");

var assert = chai.assert;

describe("jwe/implicit-headers", function() {
  var plaintext = "Well, I'm back.";
  var opts = {
    format: "compact"
  };

  describe("AES-GCM-KW", function() {
    var key = {
      "kty": "oct",
          "kid": "ojk4tyByIC1BaxTrVO0cYHaabiMZNk6MqPOLTScNQtE",
          "alg": "A256GCMKW",
          "k": "7tQn3vrNh3U9X44AO5Day_eSrms9WnV0cKel6oGljWE"
        };

    before(function() {
      return JWK.asKey(key).then(function(jwk) { key = jwk; });
    });

    it("adds a missing iv", function() {
      var p;
      p = JWE.createEncrypt(opts, key).final(plaintext, "utf8");
      p = p.then(function(result) {
        var header = result.split(".")[0];
        header = JSON.parse(util.base64url.decode(header).toString());
        assert.ok(header.iv);
        assert.ok(header.tag);
        assert.equal(util.base64url.decode(header.iv).length, 12);
        assert.equal(util.base64url.decode(header.tag).length, 16);

        return JWE.createDecrypt(key).decrypt(result);
      });
      p = p.then(function(result) {
        assert.deepEqual(result.payload.toString(), plaintext);
      });
      return p;
    });
  });

  describe("PBES2", function() {
    var key,
        pwd = "keep it secret! Keep it safe!",
        salt = util.base64url.encode("b86f66a68307d5f99b255790db605a3b", "utf8"),
        itrs = 12288;

    before(function() {
      return JWK.asKey({
        kty: "oct",
        k: util.base64url.encode(Buffer.from(pwd, "utf8")),
        alg: "PBES2-HS512+A256KW"
      }).then(function(jwk) { key = jwk; });
    });

    it("adds a missing salt", function() {
      var recipient = {
        key: key,
        header: {
          p2c: itrs
        }
      };
      var p;
      p = JWE.createEncrypt(opts, recipient).final(plaintext, "utf8");
      p = p.then(function(result) {
        var header = result.split(".")[0];
        header = JSON.parse(util.base64url.decode(header).toString());
        assert.ok(header.p2s);
        assert.ok(header.p2c);
        assert.typeOf(header.p2s, "string");
        assert.equal(header.p2c, itrs);

        return JWE.createDecrypt(key).decrypt(result);
      });
      p = p.then(function (result) {
        assert.deepEqual(result.payload.toString(), plaintext);
      });
      return p;
    });
    it("adds a missing iteration count", function() {
      var recipient = {
        key: key,
        header: {
          p2s: salt
        }
      };
      var p;
      p = JWE.createEncrypt(opts, recipient).final(plaintext, "utf8");
      p = p.then(function (result) {
        var header = result.split(".")[0];
        header = JSON.parse(util.base64url.decode(header).toString());
        assert.ok(header.p2s);
        assert.ok(header.p2c);
        assert.equal(header.p2s, salt);
        assert.equal(header.p2c, 8192);

        return JWE.createDecrypt(key).decrypt(result);
      });
      p = p.then(function (result) {
        assert.deepEqual(result.payload.toString(), plaintext);
      });
      return p;
    });
  });
});
