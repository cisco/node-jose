"use strict";

var chai = require("chai");

var JWE = require("../../lib/jwe"),
  JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/allowedalgs", function() {
  var a256kw = {
    key: {
      "kty": "oct",
      "kid": "lkSOb9wLb8VTKr0Z1TMqQoa_oSoNNn8uukn6taSuwS0",
      "k": "o9oXnnQleK4oDDN1AngQ610cn39o6Y8KPirzITJRfWw",
      "alg": "A256KW"
    },
    fields: {
      enc: "A256GCM"
    },
    plaintext: "this is not good content"
  };
  var a256gcm = {
    key: {
      "kty": "oct",
      "kid": "V5O0olRc1BSdaubnd_REP2B0xBjo8gBmNcLlv_F8hk0",
      "k": "wB_gTgRKTtYSk-ul_W-96WU92evFr01tPN6WE8A8BEU",
      "alg": "A256GCM"
    },
    plaintext: "this is very good content"
  };
  var ecdhes = {
    key: {
      "kty": "EC",
      "kid": "hpSYvh3FmNC4lQqq4Y26hdpbbgEFLIqQ3P_dxF_TiP8",
      "alg": "ECDH-ES",
      "crv": "P-256",
      "x": "bXrCXW6_ZRCzRVcRocXMehWE6MtaZM80VIEArJFYX1w",
      "y": "BKabvwMCNV_WRPoaiiSJK8wU5bAb6fJFxaIXrXgp5lI",
      "d": "zo5r2icTv5k8YKlsWcW3vDW2lb-U1DY3KUCAf9kwiK8"
    },
    fields: {
      enc: "A128GCM"
    },
    plaintext: "this is ECDH-ES content"
  };

  function decryptAllowed(vector, opts) {
    var p;
    p = JWE.createDecrypt(vector.key).
      decrypt(vector.encrypted, opts);
    p = p.then(function (result) {
      assert.strictEqual(result.payload.toString("utf8"), vector.plaintext);
    });
    return p;
  }
  function decryptDisallowed(vector, opts) {
    var p;
    p = JWE.createDecrypt(vector.key).
      decrypt(vector.encrypted, opts);
    p = p.then(function () {
      assert.ok(false, "unexpected success");
    }, function (err) {
      assert.ok(err);
    });
    return p;
  }

  before(function() {
    var pending = [ecdhes, a256gcm, a256kw].map(function(vector) {
      var p = JWK.asKey(vector.key);
      p = p.then(function(result) {
        vector.key = result;
        return result;
      });
      p = p.then(function(key) {
        return JWE.createEncrypt({ format: "compact", fields: vector.fields }, key).final(vector.plaintext, "utf8");
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
    var opts = {
      algorithms: "*"
    };

    var pending = [
      decryptAllowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });

  it("restricts on a an array of specific allowed algorithms", function() {
    var opts = {
      algorithms: ["dir", "A256GCM"]
    };

    var pending = [
      decryptDisallowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });
  it("restricts on a an array of specific allowed algorithm prefix patterns", function () {
    var opts = {
      algorithms: ["dir", "A*"]
    };

    var pending = [
      decryptDisallowed(ecdhes, opts),
      decryptAllowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });
  it("restricts on a an array of specific allowed algorithm suffix patterns", function () {
    var opts = {
      algorithms: ["dir", "ECDH-ES", "*GCM"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });

  it("restricts on a string of specific allowed algorithms", function () {
    var opts = {
      algorithms: "dir A256GCM"
    };

    var pending = [
      decryptDisallowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });
  it("restricts on a string of specific allowed algorithm prefix patterns", function () {
    var opts = {
      algorithms: "dir A*"
    };

    var pending = [
      decryptDisallowed(ecdhes, opts),
      decryptAllowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });
  it("restricts on a a string of specific allowed algorithm suffix patterns", function () {
    var opts = {
      algorithms: "dir ECDH-ES *GCM"
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts),
    ];
    return Promise.all(pending);
  });

  it("restricts on an array of ['*', negated alg] allowed algorithms", function() {
    var opts = {
      algorithms: ["*", "!A256KW"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of ['*', negated alg prefix pattern] allowed algorithms", function () {
    var opts = {
      algorithms: ["*", "!A256*"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptDisallowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of ['*', negated alg suffix pattern] allowed algorithms", function () {
    var opts = {
      algorithms: ["*", "!*KW"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });

  it("restricts on a string of '* <negated alg>' allowed algorithms", function () {
    var opts = {
      algorithms: "* !A256KW"
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });

  it("restricts on an array of [negated alg] allowed algorithms", function () {
    var opts = {
      algorithms: ["!A256KW"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of [negated alg prefix pattern] allowed algorithms", function () {
    var opts = {
      algorithms: ["!A256*"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptDisallowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of [negated alg suffix pattern] allowed algorithms", function () {
    var opts = {
      algorithms: ["!*KW"]
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });

  it("restricts on a string of '<'negated alg>' allowed algorithms", function () {
    var opts = {
      algorithms: "!A256KW"
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on a string of '<'negated alg prefix pattern>' allowed algorithms", function () {
    var opts = {
      algorithms: "!A256*"
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptDisallowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on a string of '<'negated alg suffix pattern>' allowed algorithms", function () {
    var opts = {
      algorithms: "!*KW"
    };

    var pending = [
      decryptAllowed(ecdhes, opts),
      decryptDisallowed(a256kw, opts),
      decryptAllowed(a256gcm, opts)
    ];
    return Promise.all(pending);
  });
});
