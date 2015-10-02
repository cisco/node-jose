/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

if (typeof Promise === "undefined") {
  require("es6-promise").polyfill();
}

var chai = require("chai");
var assert = chai.assert;

var jose = require("../");

describe("Public API", function() {
  it("exports JWK", function() {
    var JWK = jose.JWK;

    assert.ok(JWK);
    assert.ok(JWK.isKey);
    assert.ok(JWK.asKey);
    assert.ok(JWK.isKeyStore);
    assert.ok(JWK.asKeyStore);
    assert.ok(JWK.createKeyStore);

    assert.equal(JWK.MODE_SIGN, "sign");
    assert.equal(JWK.MODE_VERIFY, "verify");
    assert.equal(JWK.MODE_ENCRYPT, "encrypt");
    assert.equal(JWK.MODE_DECRYPT, "decrypt");
    assert.equal(JWK.MODE_WRAP, "wrap");
    assert.equal(JWK.MODE_UNWRAP, "unwrap");
  });
  it("exports JWS", function() {
    var JWS = jose.JWS;

    assert.ok(JWS);
    assert.ok(JWS.createSign);
    assert.ok(JWS.createVerify);
  });
  it("exports JWE", function() {
    var JWE = jose.JWE;

    assert.ok(JWE);
    assert.ok(JWE.createEncrypt);
    assert.ok(JWE.createDecrypt);
  });
  it("exports JWA", function() {
    var JWA = jose.JWA;

    assert.ok(JWA);
    assert.ok(JWA.digest);
    assert.ok(JWA.encrypt);
    assert.ok(JWA.decrypt);
    assert.ok(JWA.sign);
    assert.ok(JWA.verify);
  });

  it("exports util", function() {
    var util = jose.util;

    assert.ok(util);
    assert.ok(util.base64url);
    assert.ok(util.base64url.decode);
    assert.ok(util.base64url.encode);
    assert.ok(util.utf8);
    assert.ok(util.utf8.decode);
    assert.ok(util.utf8.encode);
  });

  it("exports parse", function() {
    var parse = jose.parse;

    assert.strictEqual(typeof parse, "function");
    assert.strictEqual(typeof parse.compact, "function");
    assert.strictEqual(typeof parse.json, "function");
  });
});
