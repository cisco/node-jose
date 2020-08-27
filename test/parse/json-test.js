/**
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var cloneDeep = require("lodash/cloneDeep");
var merge = require("../../lib/util/merge");
var parseJSON = require("../../lib/parse/json");

var jose = {
  JWK: require("../../lib/jwk")
};

var fixtures = {
  jws: {
    "basic": cloneDeep(require("jose-cookbook/jws/4_2.rsa-pss_signature.json")),
    "full": cloneDeep(require("jose-cookbook/jws/4_6.protecting_specific_header_fields.json")),
    "multi": cloneDeep(require("jose-cookbook/jws/4_8.multiple_signatures.json")),
    "embedded": cloneDeep(require("../fixtures/jws.embedded_jwk.json"))
  },
  jwe: {
    "basic": cloneDeep(require("jose-cookbook/jwe/5_6.direct_encryption_using_aes-gcm.json")),
    "full": cloneDeep(require("jose-cookbook/jwe/5_11.protecting_specific_header_fields.json")),
    "multi": cloneDeep(require("jose-cookbook/jwe/5_13.encrypting_to_multiple_recipients.json"))
  }
};

describe("parse/json", function() {
  describe("basic", function() {
    it("parses JWS General JSON Serialization", function() {
      var fix = fixtures.jws.basic;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      assert.deepEqual(output.all, [ fix.signing.protected ]);
      assert.deepEqual(output.input, input);

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
    it("parses JWS Flattened JSON Serialization", function() {
      var fix = fixtures.jws.basic;
      var input = fix.output.json_flat;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      assert.deepEqual(output.all, [ fix.signing.protected ]);
      assert.deepEqual(output.input, input);

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
    it("parses JWS with Embedded JWK", function() {
      var fix = fixtures.jws.embedded;
      var input = fix.output.json_flat;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      assert.deepEqual(output.all, [ fix.signing.protected ]);
      assert.deepEqual(output.input, input);

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

    it("parses JWE General JSON Serialization", function() {
      var fix = fixtures.jwe.basic;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWE");
      assert.strictEqual(output.format, "json");
      assert.deepEqual(output.all, [ fix.encrypting_content.protected ]);
      assert.deepEqual(output.input, input);

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
    it("parses JWE Flattened JSON Serialization", function() {
      var fix = fixtures.jwe.basic;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWE");
      assert.strictEqual(output.format, "json");
      assert.deepEqual(output.all, [ fix.encrypting_content.protected ]);
      assert.deepEqual(output.input, input);

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

  describe("full", function() {
    it("parses JWS General JSON Serialization", function() {
      var fix = fixtures.jws.full;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      var expected = {};
      expected = merge(expected, fix.signing.unprotected);
      expected = merge(expected, fix.signing.protected);
      assert.deepEqual(output.all, [ expected ]);
      assert.deepEqual(output.input, input);

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
    it("parses JWS Flattened JSON Serialization", function() {
      var fix = fixtures.jws.full;
      var input = fix.output.json_flat;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      var expected = {};
      expected = merge(expected, fix.signing.unprotected);
      expected = merge(expected, fix.signing.protected);
      assert.deepEqual(output.all, [ expected ]);
      assert.deepEqual(output.input, input);

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

    it("parses JWE General JSON Serialization", function() {
      var fix = fixtures.jwe.full;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWE");
      assert.strictEqual(output.format, "json");
      var expected = {};
      expected = merge(expected, fix.encrypting_content.unprotected);
      expected = merge(expected, fix.encrypting_content.protected);
      assert.deepEqual(output.all, [ expected ]);
      assert.deepEqual(output.input, input);

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
    it("parses JWE Flattened JSON Serialization", function() {
      var fix = fixtures.jwe.full;
      var input = fix.output.json_flat;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWE");
      assert.strictEqual(output.format, "json");
      var expected = {};
      expected = merge(expected, fix.encrypting_content.unprotected);
      expected = merge(expected, fix.encrypting_content.protected);
      assert.deepEqual(output.all, [ expected ]);
      assert.deepEqual(output.input, input);

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

  describe("multi", function() {
    it("parses JWS General Serialization", function() {
      var fix = fixtures.jws.multi;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWS");
      assert.strictEqual(output.format, "json");
      var expected = fix.signing.map(function(s) {
        var all = {};
        if (s.unprotected) {
          all = merge(all, s.unprotected);
        }
        if (s.protected) {
          all = merge(all, s.protected);
        }
        return all;
      });
      assert.deepEqual(output.all, expected);
      assert.deepEqual(output.input, input);

      assert.strictEqual(typeof output.perform, "function");
      var promise = jose.JWK.asKey(fix.input.key[0]);
      promise = promise.then(function(key) {
        return output.perform(key);
      });
      promise = promise.then(function(result) {
        assert.strictEqual(result.payload.toString("utf8"),
                           fix.input.payload);
      });
      return promise;
    });

    it("parses JWE General Serialization", function() {
      var fix = fixtures.jwe.multi;
      var input = fix.output.json;
      var output = parseJSON(input);
      assert.strictEqual(output.type, "JWE");
      assert.strictEqual(output.format, "json");
      var expected = fix.encrypting_key.map(function(e) {
        var all = {};
        if (e.header) {
          all = merge(all, e.header);
        }
        if (fix.encrypting_content.unprotected) {
          all = merge(all, fix.encrypting_content.unprotected);
        }
        if (fix.encrypting_content.protected) {
          all = merge(all, fix.encrypting_content.protected);
        }
        return all;
      });
      assert.deepEqual(output.all, expected);
      assert.deepEqual(output.input, input);

      assert.strictEqual(typeof output.perform, "function");
      var promise = jose.JWK.asKey(fix.input.key[0]);
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
});
