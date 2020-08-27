/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var bind = require("lodash/bind");
var clone = require("lodash/clone");
var merge = require("../../lib/util/merge");
var omit = require("lodash/omit");
var pick = require("lodash/pick");
var assert = chai.assert;

var JWK = {
  RSA: require("../../lib/jwk/rsakey.js"),
  BaseKey: require("../../lib/jwk/basekey.js"),
  store: require("../../lib/jwk/keystore.js"),
  helpers: require("../../lib/jwk/helpers.js"),
  CONSTANTS: require("../../lib/jwk/constants.js")
};
var util = require("../../lib/util");

describe("jwk/RSA", function() {
  var keyProps = {
    "kty": "RSA",
    "n": "i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q",
    "e": "AQAB",
    "d": "TgcjLjFb5FuWjDR25klXzFjR_7O1tvCPvY-ih3XAeecEnbKNY0DjOOcp3sk2J2OopAQ6oCC9jy4NK5ugZhvF8cQS8B-4unFIsIViA16dU05JK7skMOoy1dz5VYvfVvpjfl7Qsv8PadfCZnmCdfUpLuiIGL5yx7r5NjOcrCplmyApr5KJ53Qk8q76WVbZvH4bxmzoK2sOhzjH_4I4bcdlueeUj6VNZXiReY2VpldsoIgmntEy1z7DMVRjqwvBFLM7yD4P9Dlk3pfHtSMtDMyAsnaco7cAA95t1Yk60Om9RlCf_CjbmempzQ_P6Ned9VJYUvtcadqIE0lhe4Pp4POgAQ",
    "p": "y-7A4AGF8dkUjHKVXmPQ65ymWO2ACP8jR9LVrkRXd0uPXQyJqTa-233H0pqXRuMiTCnbYTr3oz4ePX53SDUsusDtWgGsrzTRozoHQoxA6cjLX-1VcjlgPpW2gzltlQWv7MBK-LaxGwlS3iuc9tuTE2vwvyPWBO3orQIF21ZoDGk",
    "q": "r3fcBfzoik-U1cL_eNb3dFCnnCt3KsBSQj0zgSKhxcdQYXkWrUgx2F0nzN98T7zjBqDcuVtdRVe8JL1HN_J5fqdjNdfCyvT5asS-MccY-fZwMsdcsT1LLLqZDWd6TsMLMpzW_dTkPTWIKWJB27-DFS61mYafvah2HfWxt8ggpoE",
    "dp": "lbOdOJNFrWTKldMjXRfu7Jag8lTeETyhvH7Dx1p5zqPUCN1ETMhYUK3DuxEqjan8qmZrmbN8yAO4lTG6BHKsdCdd1R23kyI15hmZ7Lsih7uTt8Z0XBZMVYT3ZtsIW0XCgAwkvPD3j75Ha7oeToSfMbmiD94RpKq0jBQZEosadEk",
    "dq": "OcG2RrJMyNoRH5ukA96ebUbvJNSZ0RSk_vCuN19y6GsG5k65TChrX9Cp_SHDBWwjPldM0CZmuSB76Yv0GVJS84GdgmeW0r94KdDA2hmy-vRHUi-VLzIBwKNbJbJd6_b_hJVjnwGobw1j2FtjWjXbq-lIFVTe18rPtmTdLqVNOgE",
    "qi": "YYCsHYc8qLJ1aIWnVJ9srXBC3VPWhB98tjOdK-xafhi19TeDL3OxazFV0f0FuxEGOmYeHyF4nh72wK3kRBrcosNQkAlK8oMH3Cg_AnMYehFRmDSKUFjDjXH5bVBfFk72FkmEywEaQgOiYs34P4RAEBdZohh6UTZm0-bajOkVEOE"
  };
  var keyPair;

  function formatKeyPair(json) {
    function convert(src, name) {
      this[name] = util.base64url.decode(src[name]);
    }
    var result = {
      public: {},
      private: {}
    };

    ["n", "e"].forEach(bind(convert, result.public, json));
    result.public.length = result.public.n.length * 8;

    ["n", "e", "d", "p", "q", "dp", "dq", "qi"].forEach(bind(convert, result.private, json));
    result.public.kty = result.private.kty = "RSA";
    result.public.length = result.private.length = result.public.n.length * 8;

    return result;
  }

  beforeEach(function() {
    keyPair = formatKeyPair(keyProps);
  });

  describe("#publicKey", function() {
    it("prepares a publicKey", function() {
      var props = clone(keyProps),
          actual,
          expected;

      actual = JWK.RSA.config.publicKey(props);
      expected = {
        "kty": "RSA",
        "n": util.base64url.decode("i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q"),
        "e": util.base64url.decode("AQAB"),
        length: 2048
      };
      assert.deepEqual(actual, expected);
    });
    it("prepares a publicKey with missing values", function() {
      var props,
          actual,
          expected;

      props = omit(keyProps, "n", "e");
      actual = JWK.RSA.config.publicKey(props);
      expected = {
        "kty": "RSA"
      };
      assert.deepEqual(actual, expected);

      props = omit(keyProps, "n");
      actual = JWK.RSA.config.publicKey(props);
      expected = {
        "kty": "RSA"
      };
      assert.deepEqual(actual, expected);

      props = omit(keyProps, "e");
      actual = JWK.RSA.config.publicKey(props);
      expected = {
        "kty": "RSA"
      };
      assert.deepEqual(actual, expected);
    });
  });
  describe("#privateKey", function() {
    it("prepares a privateKey", function() {
      var props = clone(keyProps),
          actual,
          expected;

      actual = JWK.RSA.config.privateKey(props);
      expected = {
        "kty": "RSA",
        "n": util.base64url.decode("i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q"),
        "e": util.base64url.decode("AQAB"),
        "d": util.base64url.decode("TgcjLjFb5FuWjDR25klXzFjR_7O1tvCPvY-ih3XAeecEnbKNY0DjOOcp3sk2J2OopAQ6oCC9jy4NK5ugZhvF8cQS8B-4unFIsIViA16dU05JK7skMOoy1dz5VYvfVvpjfl7Qsv8PadfCZnmCdfUpLuiIGL5yx7r5NjOcrCplmyApr5KJ53Qk8q76WVbZvH4bxmzoK2sOhzjH_4I4bcdlueeUj6VNZXiReY2VpldsoIgmntEy1z7DMVRjqwvBFLM7yD4P9Dlk3pfHtSMtDMyAsnaco7cAA95t1Yk60Om9RlCf_CjbmempzQ_P6Ned9VJYUvtcadqIE0lhe4Pp4POgAQ"),
        "p": util.base64url.decode("y-7A4AGF8dkUjHKVXmPQ65ymWO2ACP8jR9LVrkRXd0uPXQyJqTa-233H0pqXRuMiTCnbYTr3oz4ePX53SDUsusDtWgGsrzTRozoHQoxA6cjLX-1VcjlgPpW2gzltlQWv7MBK-LaxGwlS3iuc9tuTE2vwvyPWBO3orQIF21ZoDGk"),
        "q": util.base64url.decode("r3fcBfzoik-U1cL_eNb3dFCnnCt3KsBSQj0zgSKhxcdQYXkWrUgx2F0nzN98T7zjBqDcuVtdRVe8JL1HN_J5fqdjNdfCyvT5asS-MccY-fZwMsdcsT1LLLqZDWd6TsMLMpzW_dTkPTWIKWJB27-DFS61mYafvah2HfWxt8ggpoE"),
        "dp": util.base64url.decode("lbOdOJNFrWTKldMjXRfu7Jag8lTeETyhvH7Dx1p5zqPUCN1ETMhYUK3DuxEqjan8qmZrmbN8yAO4lTG6BHKsdCdd1R23kyI15hmZ7Lsih7uTt8Z0XBZMVYT3ZtsIW0XCgAwkvPD3j75Ha7oeToSfMbmiD94RpKq0jBQZEosadEk"),
        "dq": util.base64url.decode("OcG2RrJMyNoRH5ukA96ebUbvJNSZ0RSk_vCuN19y6GsG5k65TChrX9Cp_SHDBWwjPldM0CZmuSB76Yv0GVJS84GdgmeW0r94KdDA2hmy-vRHUi-VLzIBwKNbJbJd6_b_hJVjnwGobw1j2FtjWjXbq-lIFVTe18rPtmTdLqVNOgE"),
        "qi": util.base64url.decode("YYCsHYc8qLJ1aIWnVJ9srXBC3VPWhB98tjOdK-xafhi19TeDL3OxazFV0f0FuxEGOmYeHyF4nh72wK3kRBrcosNQkAlK8oMH3Cg_AnMYehFRmDSKUFjDjXH5bVBfFk72FkmEywEaQgOiYs34P4RAEBdZohh6UTZm0-bajOkVEOE"),
        length: 2048
      };
      assert.deepEqual(actual, expected);
    });
    it("returns undefined for missing values", function() {
      var props,
          actual;

      props = omit(keyProps, "n", "e", "d", "p", "q", "dp", "dq", "qi");
      actual = JWK.RSA.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "d");
      actual = JWK.RSA.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "n", "e");
      actual = JWK.RSA.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "p", "q");
      actual = JWK.RSA.config.privateKey(props);
      assert.deepEqual(actual, undefined);
    });
  });
  describe("#thumbprint", function() {
    var json = {
      public: {
        "n": "i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q",
        "e": "AQAB"
      }
    };
    it("returns required fields (minus kty)", function() {
      var expected = {
        "n": "i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q",
        "kty": "RSA",
        "e": "AQAB"
      };
      var actual = JWK.RSA.config.thumbprint(json);
      assert.deepEqual(actual, expected);
    });
  });
  describe("#wrapKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.RSA.config.wrapKey("RSA-OAEP", keys);
      assert.strictEqual(result, keys.public);
    });
    it("returns undefined for missing keys.public", function() {
      var keys = omit(keyPair, "public");

      var result = JWK.RSA.config.wrapKey("RSA-OAEP", keys);
      assert.isUndefined(result);
    });
  });
  describe("#unwrapKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.RSA.config.unwrapKey("RSA-OAEP", keys);
      assert.strictEqual(result, keys.private);
    });
    it("returns undefined for missing keys.private", function() {
      var keys = omit(keyPair, "private");

      var result = JWK.RSA.config.unwrapKey("RSA-OAEP", keys);
      assert.isUndefined(result);
    });
  });
  describe("#signKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.RSA.config.signKey("PS256", keys);
      assert.strictEqual(result, keys.private);
    });
    it("returns undefined for missing keys.private", function() {
      var keys = omit(keyPair, "private");

      var result = JWK.RSA.config.signKey("PS256", keys);
      assert.isUndefined(result);
    });
  });
  describe("#verifyKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.RSA.config.verifyKey("PS256", keys);
      assert.strictEqual(result, keys.public);
    });
    it("returns undefined for missing keys.public", function() {
      var keys = omit(keyPair, "public");

      var result = JWK.RSA.config.verifyKey("PS256", keys);
      assert.isUndefined(result);
    });
  });
  describe("#algorithms", function() {
    it("returns suite for public key", function() {
      var keys = pick(keyPair, "public");
      var algs;

      algs = JWK.RSA.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, []);
      algs = JWK.RSA.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, []);

      algs = JWK.RSA.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]);

      algs = JWK.RSA.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, []);

      algs = JWK.RSA.config.algorithms(keys, "sign");
      assert.deepEqual(algs, []);

      algs = JWK.RSA.config.algorithms(keys, "verify");
      assert.deepEqual(algs, ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);
    });
    it("returns suite for private key", function() {
      var keys = pick(keyPair, "private");
      var algs;

      algs = JWK.RSA.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, []);
      algs = JWK.RSA.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, []);

      algs = JWK.RSA.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, []);

      algs = JWK.RSA.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"]);

      algs = JWK.RSA.config.algorithms(keys, "sign");
      assert.deepEqual(algs, ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"]);

      algs = JWK.RSA.config.algorithms(keys, "verify");
      assert.deepEqual(algs, []);
    });
    it("exports PEM for public key", function() {
      var pem = JWK.RSA.config.convertToPEM(keyPair.public, false);
      assert.isString(pem);
      assert.match(pem, /^-----BEGIN PUBLIC KEY-----\r\n/);
      assert.match(pem, /\r\n-----END PUBLIC KEY-----\r\n$/);
    });
    it("exports PEM for private key", function() {
      var pem = JWK.RSA.config.convertToPEM(keyPair.private, true);
      assert.isString(pem);
      assert.match(pem, /^-----BEGIN RSA PRIVATE KEY-----\r\n/);
      assert.match(pem, /\r\n-----END RSA PRIVATE KEY-----\r\n$/);
    });
  });
  describe("keystore integration", function() {
    it("generates a 'RSA' JWK", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var promise = keystore.generate("RSA", 2048);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "RSA");
        assert.equal(key.length, 2048);
        assert.ok(!!key.get("n"));
        assert.ok(!!key.get("e"));
        assert.ok(!!key.get("d", true));
        assert.ok(!!key.get("p", true));
        assert.ok(!!key.get("q", true));
        assert.ok(!!key.get("dp", true));
        assert.ok(!!key.get("dq", true));
        assert.ok(!!key.get("qi", true));
      });

      return promise;
    });
    it("generates a 'RSA' JWK with props", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var props = {
        kid: "someid",
        use: "sig",
        alg: "PS256"
      };

      var promise = keystore.generate("RSA", 2048, props);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "RSA");
        assert.equal(key.length, 2048);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("use"), "sig");
        assert.equal(key.get("alg"), "PS256");
        assert.ok(!!key.get("n"));
        assert.ok(!!key.get("e"));
        assert.ok(!!key.get("d", true));
        assert.ok(!!key.get("p", true));
        assert.ok(!!key.get("q", true));
        assert.ok(!!key.get("dp", true));
        assert.ok(!!key.get("dq", true));
        assert.ok(!!key.get("qi", true));
      });

      return promise;
    });

    function setupSigKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = merge({}, keyProps, {
        kid: "someid",
        use: "sig",
        alg: "PS256"
      });

      return keystore.add(jwk);
    }
    function setupWrapKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = merge({}, keyProps, {
        kid: "someid",
        use: "enc",
        alg: "RSA-OAEP"
      });

      return keystore.add(jwk);
    }

    it("imports a 'RSA' signing JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupSigKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "RSA");
        assert.equal(key.length, 2048);
        assert.equal(key.kid, "someid");

        var json = merge({}, keyProps, {
          use: "sig",
          alg: "PS256",
          kid: "someid"
        });
        assert.deepEqual(key.toJSON(true), json);
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "5696ddb7881bfafc92c02a70e8dcafc38ade1f9508f643d293ae282d59848eb8");
      });

      return promise;
    });

    it("imports a 'RSA' wrapping JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupWrapKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "RSA");
        assert.equal(key.length, 2048);
        assert.equal(key.kid, "someid");

        var json = merge({}, keyProps, {
          use: "enc",
          alg: "RSA-OAEP",
          kid: "someid"
        });
        assert.deepEqual(key.toJSON(true), json);
        assert.deepEqual(key.toJSON(true), json);
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "5696ddb7881bfafc92c02a70e8dcafc38ade1f9508f643d293ae282d59848eb8");
      });

      return promise;
    });
  });
});
