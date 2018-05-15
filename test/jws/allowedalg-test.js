"use strict";

var chai = require("chai");

var JWS = require("../../lib/jws"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jws/allowAlgs", function () {
  var es256 = {
    key: {
      "kty": "EC",
      "kid": "_hPC_YAGupGk2LLaY7w3zVQCxw3ygXKzGI9Zd4Ip_fI",
      "use": "sig",
      "crv": "P-256",
      "x": "jTwrzgVb2nVOs6Z8shXIYbI_EtwjvfVpJFpjIBHcc0I",
      "y": "ooHASc5BUNhp1J5qyz1YyEQVQCJvfw2QclvO9XOPRow",
      "d": "bipDaYOTeo9sSEC9U7U-48YY5vckQAJ7Hu49Vdas2XM"
    },
    sig: "this is ECDSA data"
  };
  var hs256 = {
    key: {
      "kty": "oct",
      "kid": "jws-opt-test-bad",
      "k": "weCXXPzQGigKoxePr7gk9vGtPVHec_453r9vajS4dmM",
      "alg": "HS256"
    },
    sig: "this is not good data"
  };
  var hs512 = {
    key: {
      "kty": "oct",
      "kid": "jws-opt-test-good",
      "k": "zcWzNTJoq5Z2cyh6lOM7dhdCdelH0mkIV9HNcBZwzE0mrSbQdsJ-_qfOBTp6O6eDtcBHdN479WTJ5j-MTgy_bA",
      "alg": "HS512"
    },
    sig: "this is very good data"
  }

  function verifyAllowed(vector, opts) {
    var p;
    p = JWS.createVerify(vector.key).verify(vector.sig, opts);
    p = p.then(function (result) {
      assert.ok(result);
    });
    return p;
  }
  function verifyDisallowed(vector, opts) {
    var p;
    p = JWS.createVerify(vector.key).verify(vector.sig, opts);
    p = p.then(function () {
      assert.ok(false, "unexpected success");
    }, function (err) {
      assert.ok(err);
    });
    return p;
  }

  before(function () {
    var pending = [es256, hs256, hs512].map(function (vector) {
      var p = JWK.asKey(vector.key);
      p = p.then(function (result) {
        vector.key = result;
        return result;
      });
      p = p.then(function (key) {
        return JWS.createSign({ format: "compact" }, key).final(vector.sig, "utf8");
      });
      p = p.then(function (result) {
        vector.sig = result;
        return result;
      });

      return p;
    });
    return Promise.all(pending);
  });

  it("succeeds if '*' is the allowed algorithm", function () {
    var opts = {
      algorithms: "*"
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyAllowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ]
    return Promise.all(pending);
  });
  it("restricts on a string of specific alg is allowed algorithm", function () {
    var opts = {
      algorithms: "HS512"
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ]
    return Promise.all(pending);
  });
  it("restricts on a string of prefix pattern alg is allowed algorithm", function () {
    var opts = {
      algorithms: "HS*"
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyAllowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ]
    return Promise.all(pending);
  });
  it("restricts on a string of suffix pattern alg is allowed algorithm", function () {
    var opts = {
      algorithms: "*256"
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyAllowed(hs256, opts),
      verifyDisallowed(hs512, opts)
    ]
    return Promise.all(pending);
  });

  it("restricts on an array of specific alg is allowed algorithm", function () {
    var opts = {
      algorithms: ["HS512"]
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ]
    return Promise.all(pending);
  });
  it("restricts on an array of prefix pattern alg is allowed algorithm", function () {
    var opts = {
      algorithms: ["HS*"]
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyAllowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ]
    return Promise.all(pending);
  });
  it("restricts on an array of suffix pattern alg is allowed algorithm", function () {
    var opts = {
      algorithms: ["*256"]
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyAllowed(hs256, opts),
      verifyDisallowed(hs512, opts)
    ]
    return Promise.all(pending);
  });

  it("restricts on an array of ['*', negated alg] is allowed algorithm", function () {
    var opts = {
      algorithms: ["*", "!HS256"]
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of ['*', negated alg prefix pattern] is allowed algorithm", function () {
    var opts = {
      algorithms: ["*", "!HS*"]
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyDisallowed(hs512, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on an array of ['*', negated alg suffix pattern] is allowed algorithm", function () {
    var opts = {
      algorithms: ["*", "!*256"]
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ];
    return Promise.all(pending);
  });

  it("restricts on a string of '* <negated alg>' is allowed algorithm", function () {
    var opts = {
      algorithms: "* !HS256"
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on a string of '* <negated alg prefix pattern>' is allowed algorithm", function () {
    var opts = {
      algorithms: "* !HS*"
    };

    var pending = [
      verifyAllowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyDisallowed(hs512, opts)
    ];
    return Promise.all(pending);
  });
  it("restricts on a string of '* <negated alg suffix alg>' is allowed algorithm", function () {
    var opts = {
      algorithms: "* !*256"
    };

    var pending = [
      verifyDisallowed(es256, opts),
      verifyDisallowed(hs256, opts),
      verifyAllowed(hs512, opts)
    ];
    return Promise.all(pending);
  });
});
