/**
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var cloneDeep = require("lodash/cloneDeep");
var parseCompact = require("../../lib/parse/compact");
var jose = {
  JWK: require("../../lib/jwk")
};

var fixtures = {
  "jws": cloneDeep(require("jose-cookbook/jws/4_2.rsa-pss_signature.json")),
  "jws_embedded":  cloneDeep(require("../fixtures/jws.embedded_jwk.json")),
  "jwe": cloneDeep(require("jose-cookbook/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json"))
};

describe("parse/compact", function() {
  it("parses compact JWS", function() {
    var fix = fixtures.jws;
    var input = fix.output.compact;
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

  it("parses compact JWS with embedded JWK", function() {
    var fix = fixtures.jws_embedded;
    var input = fix.output.compact;
    var output = parseCompact(input);
    assert.strictEqual(output.format, "compact");
    assert.strictEqual(output.type, "JWS");
    assert.deepEqual(output.header, fix.signing.protected);
    assert.strictEqual(output.input, input);

    assert.strictEqual(typeof output.perform, "function");
    var promise = Promise.resolve();
    promise = promise.then(function() {
      return output.perform(null, {
        allowEmbeddedKey: true
      });
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
