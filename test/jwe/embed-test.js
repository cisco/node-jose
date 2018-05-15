/*!
 *
 * Copyright (c) 2016 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");

var JWK = require("../../lib/jwk");
var JWE = require("../../lib/jwe");

var assert = chai.assert;

describe("jwe/embedded", function() {
  var keys  = {
    "oct": {
      "kty": "oct",
      "kid": "BBbx9f-quvmBp5gHzO1LA1r3Fm7MsXwQovuLoIq4Des",
      "k": "rmY1vk9qj34HAYWSc2aQJg"
    }
    // TODO: RSA and EC key tests
  }

  before(function() {
    var all = Object.keys(keys);
    all = all.map(function(t) {
      return JWK.asKey(keys[t]).
             then(function(jwk) {
               keys[t] = jwk;
             });
    });
    return Promise.all(all);
  });

  describe("oct", function() {
    it("failed to embed a symmetric key", function() {
      var badKey = keys.oct;
      var opts = {
        format: "general",
        protect: false
      };
      var jwe = JWE.createEncrypt(opts, {
        key: badKey,
        reference: "jwk"
      });
      jwe.update("You shall not pass!", "utf8");
      var p = jwe.final();
      p = p.then(function() {
        assert.ok(false, "unexpected success");
      }, function(err) {
        assert.instanceOf(err, Error);
        assert.equal(err.message, "cannot embed key");
      });
      return p;
    });
  });
});
