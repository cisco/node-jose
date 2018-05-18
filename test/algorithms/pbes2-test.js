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
  var deriveVectors = [
    {
      alg: "PBKDF2-SHA-256",
      desc: "Password-based Key Derivation using HMAC-SHA-256 {password=password, salt=salt, iterations=1}",
      password: Buffer.from("password"),
      salt: Buffer.from("salt"),
      iterations: 1,
      length: 32,
      derived: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
    },
    {
      alg: "PBKDF2-SHA-256",
      desc: "Password-based Key Derivation using HMAC-SHA-256 {password=password, salt=salt, iterations=2}",
      password: Buffer.from("password"),
      salt: Buffer.from("salt"),
      iterations: 2,
      length: 32,
      derived: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
    },
    {
      alg: "PBKDF2-SHA-256",
      desc: "Password-based Key Derivation using HMAC-SHA-256 {password=password, salt=salt, iterations=4096}",
      password: Buffer.from("password"),
      salt: Buffer.from("salt"),
      iterations: 4096,
      length: 32,
      derived: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
    },
    {
      alg: "PBKDF2-SHA-256",
      desc: "Password-based Key Derivation using HMAC-SHA-256 {password=passwordPASSWORDpassword, salt=saltSALTsaltSALTsaltSALTsaltSALTsalt, iterations=4096}",
      password: Buffer.from("passwordPASSWORDpassword"),
      salt: Buffer.from("saltSALTsaltSALTsaltSALTsaltSALTsalt"),
      iterations: 4096,
      length: 40,
      derived: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
    }
  ];
  deriveVectors.forEach(function(v) {
    var key = v.password,
        props = {
          salt: v.salt,
          iterations: v.iterations,
          length: v.length
        },
        derived = v.derived;

    it("performs " + v.alg + " (" + v.desc + ")", function() {
      var promise = algorithms.derive(v.alg, key, props);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), derived);
      });
      return promise;
    });
  });

  var encVectors = [
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

  encVectors.forEach(function(v) {
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
        assert.equal(result.header.p2s, util.base64url.encode(v.salt));
        assert.equal(result.header.p2c, v.iterations);
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

  describe("defaults", function() {
    var vectors = [
      {
        alg: "PBES2-HS256+A128KW",
        desc: "Password-Based Encryption using HMAC-SHA-256 and AES-128-KW",
        password: util.base64url.decode("ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"),
        salt: "8Q1SzinasR3xchYz6ZZcHA",
        iterations: 8192,
        plaintext: util.base64url.decode("pqampqampqampqampqampg")
      },
      {
        alg: "PBES2-HS512+A256KW",
        desc: "Password-Based Encryption using HMAC-SHA-512 and AES-256-KW",
        password: util.base64url.decode("ZW50cmFwX2_igJNwZXRlcl9sb25n4oCTY3JlZGl0X3R1bg"),
        salt: "8Q1SzinasR3xchYz6ZZcHA",
        iterations: 8192,
        plaintext: util.base64url.decode("pqampqampqampqampqampqampqampqampqampqampqY")
      }
    ];

    vectors.forEach(function(v) {
      it("applies a default iteration count when missing from " + v.alg, function () {
        var key = v.password,
            props = {
              p2s: v.salt
            },
            pdata = v.plaintext,
            cdata;

        var p = Promise.resolve();
        p = p.then(function() {
          return algorithms.encrypt(v.alg, key, pdata, props);
        });
        p = p.then(function(result) {
          var header = result.header;
          assert.ok(header);
          assert.equal(header.p2s, v.salt);
          assert.equal(header.p2c, 8192);
          props = header;
          cdata = result.data;
        });
        p = p.then(function() {
          return algorithms.decrypt(v.alg, key, cdata, props);
        });
        return p;
      });

      it("applies a valid salt when missing from " + v.alg, function () {
        var key = v.password,
          props = {
            p2c: v.iterations
          },
          pdata = v.plaintext,
          cdata;

        var p = Promise.resolve();
        p = p.then(function () {
          return algorithms.encrypt(v.alg, key, pdata, props);
        });
        p = p.then(function (result) {
          var header = result.header;
          assert.ok(header);
          assert.typeOf(header.p2s, "string");
          assert.equal(header.p2c, v.iterations);
          props = header;
          cdata = result.data;
        });
        p = p.then(function () {
          return algorithms.decrypt(v.alg, key, cdata, props);
        });
        return p;
      });
    });
  })
});
