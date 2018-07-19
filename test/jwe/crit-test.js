"use strict";

var chai = require("chai");

var JWE = require("../../lib/jwe"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/crit", function() {
  var key = {
    "kty": "oct",
    "kid": "jws-crit-test",
    "k": "weCXXPzQGigKoxePr7gk9vGtPVHec_453r9vajS4dmM",
    "alg": "A256GCM"
  };

  before(function() {
    return JWK.asKey(key).
          then(function(result) {
            key = result;
          });
  });
  it("by default fails decrypt if 'crit' is specified", function() {
    var opts = {
      fields: {
        crit: ["exp"],
        exp: Date.now()
      }
    };
    var jwe = JWE.createEncrypt(opts, key);
    jwe.update(Buffer.from("something that should fail"));
    var p = jwe.final();
    p = p.then(function(jwe) {
      return JWE.createDecrypt(key).
             decrypt(jwe).
             then(function() {
               assert.ok(false, "unexpected success");
             }, function(err) {
               assert.ok(err instanceof Error);
             });
    });
    return p;
  });
  it("succeeds if opts.handlers has a boolean property for 'crit'", function() {
    var opts = {
      fields: {
        crit: ["exp"],
        exp: Date.now()
      },
      handlers: {
        exp: true
      }
    };
    var jwe = JWE.createEncrypt(opts, key);
    jwe.update(Buffer.from("something that should not fail"));
    var p = jwe.final();
    p = p.then(function(jwe) {
      return JWE.createDecrypt(key).
             decrypt(jwe, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
  it("succeeds if opts.handlers has a function property for 'crit'", function() {
    var opts;
    opts = {
      fields: {
        crit: ["exp"],
        exp: Date.now()
      },
      handlers: {
        exp: function(jwe) {
          assert.equal(jwe.header.exp, opts.fields.exp);
        }
      }
    };
    var jwe = JWE.createEncrypt(opts, key);
    jwe.update(Buffer.from("something that should not fail"));
    var p = jwe.final();
    p = p.then(function(jwe) {
      return JWE.createDecrypt(key).
             decrypt(jwe, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
  it("succeeds if opts.handlers has an object property for 'crit'", function() {
    var opts;
    opts = {
      fields: {
        crit: ["exp"],
        exp: 1450474323149
      },
      handlers: {
        exp: {
          prepare: function(jwe) {
            assert.ok(JWK.isKey(jwe.key));
            assert.equal(typeof jwe.header, "object");
            assert.ok(Array.isArray(jwe.protected));
            assert.equal(typeof jwe.iv, "string");
            assert.equal(typeof jwe.tag, "string");
            assert.equal(typeof jwe.ciphertext, "string");
          },
          complete: function(jwe) {
            assert.ok(JWK.isKey(jwe.key));
            assert.equal(typeof jwe.header, "object");
            assert.ok(Array.isArray(jwe.protected));
            assert.ok(Buffer.isBuffer(jwe.payload));
          }
        }
      }
    };
    var jwe = JWE.createEncrypt(opts, key);
    jwe.update(Buffer.from("something that should not fail"));
    var p = jwe.final();
    p = p.then(function(jwe) {
      return JWE.createDecrypt(key).
             decrypt(jwe, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
});
