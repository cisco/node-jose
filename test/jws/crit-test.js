"use strict";

var chai = require("chai");

var JWS = require("../../lib/jws"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jws/crit", function() {
  var key = {
    "kty": "oct",
    "kid": "jws-crit-test",
    "k": "weCXXPzQGigKoxePr7gk9vGtPVHec_453r9vajS4dmM",
    "alg": "HS256"
  };

  before(function() {
    return JWK.asKey(key).
          then(function(result) {
            key = result;
          });
  });
  it("by default fails verify if 'crit' is specified", function() {
    var opts = {
      fields: {
        crit: ["exp"]
      }
    };
    var jws = JWS.createSign(opts, key);
    jws.update(Buffer.from("something that should fail"));
    var p = jws.final();
    p = p.then(function(jws) {
      return JWS.createVerify(key).
             verify(jws).
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
    var jws = JWS.createSign(opts, key);
    jws.update(Buffer.from("something that should not fail"));
    var p = jws.final();
    p = p.then(function(jws) {
      return JWS.createVerify(key).
             verify(jws, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
  it("succeeds if opts.handlers has a function property for 'crit'", function() {
    var opts = {
      fields: {
        crit: ["exp"],
        exp: Date.now()
      },
      handlers: {
        exp: function(jws) {
          assert.ok(JWK.isKey(jws.key));
          assert.equal(typeof jws.header, "object");
          assert.ok(Array.isArray(jws.protected));
          assert.equal(typeof jws.payload, "string");
          assert.ok(-1 !== jws.protected.indexOf("crit"));
          assert.equal(jws.header.exp, opts.fields.exp);
        }
      }
    };
    var jws = JWS.createSign(opts, key);
    jws.update(Buffer.from("something that should not fail"));
    var p = jws.final();
    p = p.then(function(jws) {
      return JWS.createVerify(key).
             verify(jws, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
  it("succeeds if opts.handlers has an object property for 'crit'", function() {
    var opts = {
      fields: {
        crit: ["exp"],
        exp: Date.now()
      },
      handlers: {
        exp: {
          prepare: function(jws) {
            assert.ok(JWK.isKey(jws.key));
            assert.equal(typeof jws.header, "object");
            assert.ok(Array.isArray(jws.protected));
            assert.equal(typeof jws.payload, "string");
            assert.ok(-1 !== jws.protected.indexOf("crit"));
            assert.equal(jws.header.exp, opts.fields.exp);
          },
          complete: function(jws) {
            assert.ok(JWK.isKey(jws.key));
            assert.equal(typeof jws.header, "object");
            assert.ok(Array.isArray(jws.protected));
            assert.ok(Buffer.isBuffer(jws.payload));
            assert.ok(-1 !== jws.protected.indexOf("crit"));
            assert.equal(jws.header.exp, opts.fields.exp);
          }
        }
      }
    };
    var jws = JWS.createSign(opts, key);
    jws.update(Buffer.from("something that should not fail"));
    var p = jws.final();
    p = p.then(function(jws) {
      return JWS.createVerify(key).
             verify(jws, opts).
             then(function(result) {
               assert.ok(result);
             });
    });
    return p;
  });
});
