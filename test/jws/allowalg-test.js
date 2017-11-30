"use strict";

var chai = require("chai");

var JWS = require("../../lib/jws"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jws/allowAlgs", function() {
  var bad = {
    key: {
      "kty": "oct",
      "kid": "jws-opt-test-bad",
      "k": "weCXXPzQGigKoxePr7gk9vGtPVHec_453r9vajS4dmM",
      "alg": "HS256"
    },
    sig: "this is not good data"
  };
  var good = {
    key: {
      "kty": "oct",
      "kid": "jws-opt-test-good",
      "k": "zcWzNTJoq5Z2cyh6lOM7dhdCdelH0mkIV9HNcBZwzE0mrSbQdsJ-_qfOBTp6O6eDtcBHdN479WTJ5j-MTgy_bA",
      "alg": "HS512"
    },
    sig: "this is very good data"
  }

  before(function() {
    var pending = [bad, good].map(function(vector) {
      var p = JWK.asKey(vector.key);
      p = p.then(function(result) {
        vector.key = result;
        return result;
      });
      p = p.then(function(key) {
        return JWS.createSign({ format: "compact" }, key).final(vector.sig, "utf8");
      });
      p = p.then(function(result) {
        vector.sig = result;
        return result;
      });

      return p;
    });
    return Promise.all(pending);
  });

  it("succeeeds if '*' is the allowed algorithm", function() {
    var pending = [];
    var opts = {
      algorithms: "*"
    };

    pending.push(function() {
      var p;
      p = JWS.createVerify(good.key).verify(good.sig, opts);
      p = p.then(function(result) {
        assert.ok(result);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWS.createVerify(bad.key).verify(bad.sig, opts);
      p = p.then(function (result) {
        assert.ok(result);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on a string of specific alg is allowed algorithm", function() {
    var pending = [];
    var opts = {
      algorithms: "HS512"
    };

    pending.push(function () {
      var p;
      p = JWS.createVerify(good.key).verify(good.sig, opts);
      p = p.then(function (result) {
        assert.ok(result);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWS.createVerify(bad.key).verify(bad.sig, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function(err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on an array of specific alg is allowed algorithm", function () {
    var pending = [];
    var opts = {
      algorithms: ["HS512"]
    };

    pending.push(function () {
      var p;
      p = JWS.createVerify(good.key).verify(good.sig, opts);
      p = p.then(function (result) {
        assert.ok(result);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWS.createVerify(bad.key).verify(bad.sig, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on an array of ['*', negated alg] is allowed algorithm", function () {
    var pending = [];
    var opts = {
      algorithms: ["*", "!HS256"]
    };

    pending.push(function () {
      var p;
      p = JWS.createVerify(good.key).verify(good.sig, opts);
      p = p.then(function (result) {
        assert.ok(result);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWS.createVerify(bad.key).verify(bad.sig, opts);
      p = p.then(function (result) {
        assert.ok(false, "unexpected success");
      }, function (err) {
        assert.ok(err);
      });
      return p;
    });

    return Promise.all(pending);
  });
  it("restricts on an array of '* <negated alg>' is allowed algorithm", function () {
    var pending = [];
    var opts = {
      algorithms: "* !*256"
    };

    pending.push(function () {
      var p;
      p = JWS.createVerify(good.key).verify(good.sig, opts);
      p = p.then(function (result) {
        assert.ok(result);
      });
      return p;
    });
    pending.push(function () {
      var p;
      p = JWS.createVerify(bad.key).verify(bad.sig, opts);
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
