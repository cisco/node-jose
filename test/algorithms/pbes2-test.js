/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/"),
    util = require("../../lib/util");

describe("algorithms/pbes2", function() {
  var vectors = [
    {
      alg: "PBES2-HS256+A128KW",
      desc: "Password-Based Encryption using HMAC-SHA-256 and AES-128-KW",
      password: util.base64url.decode("ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"),
      salt: util.base64url.decode("8Q1SzinasR3xchYz6ZZcHA"),
      iterations: 8192,
      plaintext: util.base64url.decode("pqampqampqampqampqampg"),
      ciphertext: util.base64url.decode("walEclCCkwmSDoXll-vLE0DRuOCfXc3N")
    },
    /* NOTE: 192-bit AES not supported universally
    {
      alg: "PBES2-HS384+A192KW",
      desc: "Password-Based Encryption using HMAC-SHA-384 and AES-192-KW",
      password: util.base64url.decode("cGFzc3dvcmQ"),
      salt: util.base64url.decode("c2FsdA"),
      iterations: 1,
      plaintext: util.base64url.decode("pqampqampqampqampqampg"),
      ciphertext: util.base64url.decode("8dZ5AQ31AOhKRUwQ0l3-SxDCpqCnXlmz")
    },
    //*/
    {
      alg: "PBES2-HS512+A256KW",
      desc: "Password-Based Encryption using HMAC-SHA-512 and AES-256-KW",
      password: util.base64url.decode("ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"),
      salt: util.base64url.decode("8Q1SzinasR3xchYz6ZZcHA"),
      iterations: 8192,
      plaintext: util.base64url.decode("pqampqampqampqampqampqampqampqampqampqampqY"),
      ciphertext: util.base64url.decode("KPq3dK9i8YFo6moWueJlgJ1XAQKRM4u_P1UaQyMs1C8VNTTyDLe9Lw")
    }
  ];

  vectors.forEach(function(v) {
    var key = v.password,
        props = {
          p2s: v.salt,
          p2c: v.iterations
        },
        pdata = v.plaintext,
        cdata = v.ciphertext;

    var encrunner = function() {
      var promise = algorithms.encrypt(v.alg, key, pdata, props);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), cdata.toString("hex"));
      });
      return promise;
    };
    var decrunner = function() {
      var promise = algorithms.decrypt(v.alg, key, cdata, props);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), pdata.toString("hex"));
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") encryption", encrunner);
    it("performs " + v.alg + " (" + v.desc + ") decryption", decrunner);
  });
});
