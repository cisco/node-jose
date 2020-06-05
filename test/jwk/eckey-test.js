/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai"),
    bind = require("lodash/bind"),
    clone = require("lodash/clone"),
    merge = require("../../lib/util/merge"),
    omit = require("lodash/omit"),
    pick = require("lodash/pick");
var assert = chai.assert;

var JWK = {
  EC: require("../../lib/jwk/eckey.js"),
  BaseKey: require("../../lib/jwk/basekey.js"),
  store: require("../../lib/jwk/keystore.js"),
  helpers: require("../../lib/jwk/helpers.js"),
  CONSTANTS: require("../../lib/jwk/constants.js"),
  ecutil: require("../../lib/algorithms/ec-util.js")
};
var util = require("../../lib/util");

describe("jwk/EC", function() {
  var keyProps = {
    "kty": "EC",
    "crv": "P-256",
    "x": "uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak",
    "y": "v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM",
    "d": "dI5TRpZrVLpTr_xxYK-n8FgTBpe5Uer-8QgHu5gx9Ds"
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

    result.public.kty = result.private.kty = "EC";
    result.public.crv = result.private.crv = json.crv;
    ["x", "y"].forEach(bind(convert, result.public, json));
    ["x", "y", "d"].forEach(bind(convert, result.private, json));
    result.public.length = result.private.length = JWK.ecutil.curveSize(json.crv);

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
      actual = JWK.EC.config.publicKey(props);
      expected = {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak"),
        "y": util.base64url.decode("v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"),
        length: 256
      };
      assert.deepEqual(actual, expected);
    });
    it("prepares a publicKey with missing values", function() {
      var props,
          actual,
          expected;

      props = omit(keyProps, "crv", "x", "y");
      actual = JWK.EC.config.publicKey(props);
      expected = {
        "kty": "EC"
      };
      assert.deepEqual(actual, expected);

      props = omit(keyProps, "x");
      actual = JWK.EC.config.publicKey(props);
      expected = {
        "kty": "EC"
      };
      assert.deepEqual(actual, expected);

      props = omit(keyProps, "y");
      actual = JWK.EC.config.publicKey(props);
      expected = {
        "kty": "EC"
      };
      assert.deepEqual(actual, expected);
    });
  });
  describe("#privateKey", function() {
    it("prepares a privateKey", function() {
      var props = clone(keyProps),
          actual,
          expected;
      actual = JWK.EC.config.privateKey(props);
      expected = {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak"),
        "y": util.base64url.decode("v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"),
        "d": util.base64url.decode("dI5TRpZrVLpTr_xxYK-n8FgTBpe5Uer-8QgHu5gx9Ds"),
        length: 256
      };
      assert.deepEqual(actual, expected);
    });
    it("prepares a privateKey with missing values", function() {
      var props,
          actual;

      props = omit(keyProps, "crv", "x", "y", "d");
      actual = JWK.EC.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "d");
      actual = JWK.EC.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "d");
      actual = JWK.EC.config.privateKey(props);
      assert.deepEqual(actual, undefined);

      props = omit(keyProps, "x", "y");
      actual = JWK.EC.config.privateKey(props);
      assert.deepEqual(actual, undefined);
    });
  });
  describe("#thumbprint", function() {
    var json = {
      public: {
        "kty": "EC",
        "crv": "P-256",
        "x": "uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak",
        "y": "v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"
      }
    };
    it("returns required fields (minus kty)", function() {
      var expected = {
        "crv": "P-256",
        "kty": "EC",
        "x": "uiOfViX69jYwnygrkPkuM0XqUlvW65WEs_7rgT3eaak",
        "y": "v8S-ifVFkNLoe1TSUrNFQVj6jRbK1L8V-eZa-ngsZLM"
      };
      var actual = JWK.EC.config.thumbprint(json);
      assert.deepEqual(actual, expected);
    });
  });

  describe("#wrapKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.EC.config.wrapKey("ECDH-ES", keys);
      assert.strictEqual(result, keys.public);
    });
    it("returns undefined for missing keys.public", function() {
    var keys = omit(keyPair, "public");

    var result = JWK.EC.config.wrapKey("ECDH-ES", keys);
    assert.isUndefined(result);
    });
  });
  describe("#unwrapKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.EC.config.unwrapKey("ECDH-ES", keys);
      assert.strictEqual(result, keys.private);
    });
    it("returns undefined for missing keys.private", function() {
      var keys = omit(keyPair, "private");

      var result = JWK.EC.config.unwrapKey("ECDH-ES", keys);
      assert.isUndefined(result);
    });
  });
  describe("#signKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.EC.config.signKey("ES256", keys);
      assert.strictEqual(result, keys.private);
    });
    it("returns undefined for missing keys.private", function() {
      var keys = omit(keyPair, "private");

      var result = JWK.EC.config.signKey("ES256", keys);
      assert.isUndefined(result);
    });
  });
  describe("#verifyKey", function() {
    it("returns key value", function() {
      var keys = clone(keyPair);

      var result = JWK.EC.config.verifyKey("ES256", keys);
      assert.strictEqual(result, keys.public);
    });
    it("returns undefined for missing keys.public", function() {
      var keys = omit(keyPair, "public");

      var result = JWK.EC.config.verifyKey("ES256", keys);
      assert.isUndefined(result);
    });
  });
  describe("#algorithms", function() {
    it("returns suite for public key", function() {
      var keys = pick(keyPair, "public");
      var algs;

      algs = JWK.EC.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, []);
      algs = JWK.EC.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, []);

      algs = JWK.EC.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]);

      algs = JWK.EC.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, []);

      algs = JWK.EC.config.algorithms(keys, "sign");
      assert.deepEqual(algs, []);

      algs = JWK.EC.config.algorithms(keys, "verify");
      assert.deepEqual(algs, ["ES256"]);
    });
    it("returns suite for private key", function() {
      var keys = pick(keyPair, "private");
      var algs;

      algs = JWK.EC.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, []);
      algs = JWK.EC.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, []);

      algs = JWK.EC.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, []);

      algs = JWK.EC.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]);

      algs = JWK.EC.config.algorithms(keys, "sign");
      assert.deepEqual(algs, ["ES256"]);

      algs = JWK.EC.config.algorithms(keys, "verify");
      assert.deepEqual(algs, []);
    });
    it("exports PEM for public key", function() {
      var pem = JWK.EC.config.convertToPEM(keyPair.public, false);
      assert.isString(pem);
      assert.match(pem, /^-----BEGIN PUBLIC KEY-----\r\n/);
      assert.match(pem, /\r\n-----END PUBLIC KEY-----\r\n$/);
    });
    it("exports PEM for private key", function() {
      var pem = JWK.EC.config.convertToPEM(keyPair.private, true);
      assert.isString(pem);
      assert.match(pem, /^-----BEGIN EC PRIVATE KEY-----\r\n/);
      assert.match(pem, /\r\n-----END EC PRIVATE KEY-----\r\n$/);
    });
  });
  describe("keystore integration", function() {
    it("generates a 'EC' JWK", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var promise = keystore.generate("EC", "P-256");
      promise = promise.then(function(key) {
        assert.equal(key.kty, "EC");
        assert.equal(key.length, 256);
        assert.equal(key.get("crv"), "P-256");
        assert.ok(!!key.get("x"));
        assert.ok(!!key.get("y"));
        assert.ok(!!key.get("d", true));
      });

      return promise;
    });
    it("generates a 'EC' JWK with props", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var props = {
        kid: "someid",
        use: "sig",
        alg: "ES256"
      };

      var promise = keystore.generate("EC", "P-256", props);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "EC");
        assert.equal(key.length, 256);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("use"), "sig");
        assert.equal(key.get("alg"), "ES256");
        assert.equal(key.get("crv"), "P-256");
        assert.ok(!!key.get("x"));
        assert.ok(!!key.get("y"));
        assert.ok(!!key.get("d", true));
      });

      return promise;
    });

    function setupSigKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = merge({}, keyProps, {
        kid: "someid",
        use: "sig",
        alg: "ES256"
      });

      return keystore.add(jwk);
    }
    function setupWrapKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = merge({}, keyProps, {
        kid: "someid",
        use: "enc",
        alg: "ECDH-ES"
      });

      return keystore.add(jwk);
    }

    it("imports a 'EC' signing JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupSigKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "EC");
        assert.equal(key.length, 256);
        assert.equal(key.kid, "someid");

        var json = merge({}, keyProps, {
          use: "sig",
          alg: "ES256",
          kid: "someid"
        });
        assert.deepEqual(key.toJSON(true), json);
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "c840ce5ed3b9c62facb05e82ac8e70b4fa4c47c456a5f98ae0cbe5a3e2ebcea5");
      });

      return promise;
    });
    it("imports a 'EC' wrapping JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupWrapKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "EC");
        assert.equal(key.length, 256);
        assert.equal(key.kid, "someid");

        var json = merge({}, keyProps, {
          use: "enc",
          alg: "ECDH-ES",
          kid: "someid"
        });
        assert.deepEqual(key.toJSON(true), json);
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "c840ce5ed3b9c62facb05e82ac8e70b4fa4c47c456a5f98ae0cbe5a3e2ebcea5");
      });
      return promise;
    });
  });
});
