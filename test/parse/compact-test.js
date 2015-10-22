/**
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var cloneDeep = require("lodash.clonedeep");
var parseCompact = require("../../lib/parse/compact");
var jose = {
  JWK: require("../../lib/jwk")
};

var fixtures = {
  "jws": cloneDeep(require("jose-cookbook/jws/4_1.rsa_v15_signature.json")),
  "jwe": cloneDeep(require("jose-cookbook/jwe/5_1.key_encryption_using_rsa_v15_and_aes-hmac-sha2.json"))
};

describe("parse/compact", function() {
  it("parses compact JWS", function() {
    var fix = fixtures.jws;
    var input = fixtures.jws.output.compact;
    var output = parseCompact(input);
    assert.strictEqual(output.format, "compact");
    assert.strictEqual(output.type, "JWS");
    assert.deepEqual(output.header, fix.signing.protected);
    assert.strictEqual(output.input, input);

    assert.strictEqual(typeof output.perform, "function");
    var promise = jose.JWK.asKey(fix.input.key);
    promise = promise.then(function(key) {
      return output.perform(key);
    });
    promise = promise.then(function(result) {
      assert.strictEqual(result.payload.toString("utf8"),
                         fix.input.payload);
    });
    return promise;
  });
  it("parses compact JWE", function() {
    var fix = fixtures.jwe;
    var input = fix.output.compact;
    var output = parseCompact(input);
    assert.strictEqual(output.format, "compact");
    assert.strictEqual(output.type, "JWE");
    assert.deepEqual(output.header, fix.encrypting_content.protected);
    assert.strictEqual(output.input, input);

    assert.strictEqual(typeof output.perform, "function");
    var promise = jose.JWK.asKey(fix.input.key);
    promise = promise.then(function(key) {
      return output.perform(key);
    });
    promise = promise.then(function(result) {
      assert.strictEqual(result.plaintext.toString("utf8"),
                         fix.input.plaintext);
    });
    return promise;
  });
});
