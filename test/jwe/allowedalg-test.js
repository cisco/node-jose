"use strict";

var chai = require("chai");

var JWE = require("../../lib/jwe"),
  JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/allowedalgs", function() {
  var bad = {
    key: {
      "kty": "oct",
      "kid": "lkSOb9wLb8VTKr0Z1TMqQoa_oSoNNn8uukn6taSuwS0",
      "k": "o9oXnnQleK4oDDN1AngQ610cn39o6Y8KPirzITJRfWw",
      "alg": "A256KW"
    },
    plaintext: "this is not good content"
  };
  var good = {
    key: {
      "kty": "oct",
      "kid": "V5O0olRc1BSdaubnd_REP2B0xBjo8gBmNcLlv_F8hk0",
      "k": "wB_gTgRKTtYSk-ul_W-96WU92evFr01tPN6WE8A8BEU",
      "alg": "A256GCM"
    },
    plaintext: "this is very good content"
  };

  before(function() {
    var pending = [good, bad].map(function(vector) {
      var p = JWK.asKey(vector.key);
      p = p.then(function(result) {
        vector.key = result;
        return result;
      });
      p = p.then(function(key) {
        return JWE.createEncrypt({ format: "compact" }, key).final(vector.plaintext, "utf8");
      });
      p = p.then(function(result) {
        vector.encrypted = result;
        return result;
      });
      return p;
    });
    return Promise.all(pending);
  });

  it("succeeds if '*' is allowed algorithms", function() {
    var pending = [];
    var opts = {
      algorithms: "*"
    };

    pending.push(function() {
      var p;
      p = JWE.createDecrypt(good.key).
          decrypt(good.encrypted, opts);
      p = p.then(function(result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.strictEqual(result.payload.toString("utf8"), bad.plaintext);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on a an array of algs", function() {
    var pending = [];
    var opts = {
      algorithms: ["dir", "A*GCM"]
    };

    pending.push(function() {
      var p;

      p = JWE.createDecrypt(good.key).
          decrypt(good.encrypted, opts);
      p = p.then(function(result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;

      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function(err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on a string of algs", function () {
    var pending = [];
    var opts = {
      algorithms: "dir A*GCM"
    };

    pending.push(function () {
      var p;

      p = JWE.createDecrypt(good.key).
        decrypt(good.encrypted, opts);
      p = p.then(function (result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;

      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on ['*', negated alg] is allowed algorithms", function() {
    var pending = [];
    var opts = {
      algorithms: ["*", "!A*KW"]
    };

    pending.push(function () {
      var p;

      p = JWE.createDecrypt(good.key).
        decrypt(good.encrypted, opts);
      p = p.then(function (result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;

      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on [negated alg] is allowed algorithms", function () {
    var pending = [];
    var opts = {
      algorithms: ["!A*KW"]
    };

    pending.push(function () {
      var p;

      p = JWE.createDecrypt(good.key).
        decrypt(good.encrypted, opts);
      p = p.then(function (result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;

      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on just '<'negated alg>' is allowed algorithms", function () {
    var pending = [];
    var opts = {
      algorithms: "!A*KW"
    };

    pending.push(function () {
      var p;

      p = JWE.createDecrypt(good.key).
        decrypt(good.encrypted, opts);
      p = p.then(function (result) {
        assert.strictEqual(result.payload.toString("utf8"), good.plaintext);
      });
      return p;
    });
    pending.push(function () {
      var p;

      p = JWE.createDecrypt(bad.key).
        decrypt(bad.encrypted, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
});
