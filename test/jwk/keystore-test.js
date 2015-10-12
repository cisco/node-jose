/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai"),
    forge = require("node-forge");
var assert = chai.assert;

var JWK = {
  store: require("../../lib/jwk/keystore.js"),
  BaseKey: require("../../lib/jwk/basekey.js"),
  helpers: require("../../lib/jwk/helpers.js"),
  CONSTANTS: require("../../lib/jwk/constants.js")
};
var util = require("../../lib/util");

var DUMMY_FACTORY = {
  kty: "DUMMY",
  config: {
    publicKey: function(props) {
      var fields = JWK.helpers.COMMON_PROPS.concat([
        {name: "pub", type: "binary"}
      ]);

      var pk;
      pk = JWK.helpers.unpackProps(props, fields);
      pk.length = (pk.pub && pk.pub.length || 0) * 8;

      return pk;
    },
    privateKey: function(props) {
      var fields = JWK.helpers.COMMON_PROPS.concat([
        {name: "prv", type: "binary"}
      ]);

      var pk;
      pk = JWK.helpers.unpackProps(props, fields);
      pk.length = (pk.prv && pk.prv.length || 0) * 8;

      return pk;
    }
  },
  generate: function(size) {
    if ((size !== 128) &&
        (size !== 192) &&
        (size !== 256)) {
      Promise.reject(new Error("invalid key size"));
    }

    // NOT A REAL KEY
    var props = {
      pub: new Buffer(forge.random.getBytes(size / 8), "binary"),
      prv: new Buffer(forge.random.getBytes(size / 8), "binary")
    };

    return Promise.resolve(props);
  },
  prepare: function() {
    return Promise.resolve(DUMMY_FACTORY.config);
  }
};

describe("jwk/registry", function() {
  it("registers and unregisters a factory", function() {
    var registry = new JWK.store.KeyRegistry();

    var type = registry.get("DUMMY");
    assert.isUndefined(type);
    assert.isUndefined(registry.get(""));
    assert.isUndefined(registry.get());

    assert.strictEqual(registry.register(DUMMY_FACTORY), registry);
    type = registry.get("DUMMY");
    assert.strictEqual(type, DUMMY_FACTORY);
    assert.isUndefined(registry.get(""));
    assert.isUndefined(registry.get());

    assert.strictEqual(registry.unregister(DUMMY_FACTORY), registry);
    type = registry.get("DUMMY");
    assert.isUndefined(type);
    assert.isUndefined(registry.get(""));
    assert.isUndefined(registry.get());

    assert.strictEqual(registry.unregister(DUMMY_FACTORY), registry);
    type = registry.get("DUMMY");
    assert.isUndefined(type);
    assert.isUndefined(registry.get(""));
    assert.isUndefined(registry.get());
  });
  it("rejects an invalid factory when registering", function() {
    var registry = new JWK.store.KeyRegistry();

    assert.throw(function() {
      registry.register(null);
    }, "invalid Key factory");
    assert.throw(function() {
      registry.register({});
    }, "invalid Key factory");
  });
  it("rejects an invalid factory when registering", function() {
    var registry = new JWK.store.KeyRegistry();

    assert.throw(function() {
      registry.unregister(null);
    }, "invalid Key factory");
    assert.throw(function() {
      registry.unregister({});
    }, "invalid Key factory");
  });
});
describe("jwk/keystore", function() {
  var REGISTRY = new JWK.store.KeyRegistry();
  before(function() {
    REGISTRY.register(DUMMY_FACTORY);
  });

  function createInstance() {
    return new JWK.store.KeyStore(REGISTRY);
  }

  describe("add/remove", function() {
    it("adds/removes a key as JSON", function() {
      var jwk = {
        "kty": "DUMMY",
        "kid": "someid",
        "use": "sig",
        "alg": "HS256",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      };
      var keystore = createInstance();

      var promise = keystore.add(jwk);
      assert.ok("function" === typeof promise.then);
      promise = promise.then(function(key) {
        // is a key ...
        assert.ok(JWK.store.KeyStore.isKey(key));
        assert.deepEqual(key.toObject(true), {
          "kty": "DUMMY",
          "kid": "someid",
          "use": "sig",
          "alg": "HS256",
          "pub": new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
        });

        // ... and exists in the keystore
        assert.deepEqual(keystore.all(), [key]);

        return key;
      });

      promise = promise.then(function(key) {
        keystore.remove(key);

        assert.deepEqual(keystore.all(), []);
      });

      return promise;
    });
    it("adds/removes a key as a string", function() {
      var jwk = JSON.stringify({
        "kty": "DUMMY",
        "kid": "someid",
        "use": "sig",
        "alg": "HS256",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      });
      var keystore = createInstance();

      var promise = keystore.add(jwk);
      assert.ok("function" === typeof promise.then);
      promise = promise.then(function(key) {
        // is a key ...
        assert.ok(JWK.store.KeyStore.isKey(key));
        assert.deepEqual(key.toObject(true), {
          "kty": "DUMMY",
          "kid": "someid",
          "use": "sig",
          "alg": "HS256",
          "pub": new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
        });

        // ... and exists in the keystore
        assert.deepEqual(keystore.all(), [key]);

        return key;
      });

      promise = promise.then(function(key) {
        keystore.remove(key);

        assert.deepEqual(keystore.all(), []);
      });

      return promise;
    });
    it("adds/removes a key as a JWK.Key object", function() {
      var jwk = {
        "kty": "DUMMY",
        "kid": "someid",
        "use": "sig",
        "alg": "HS256",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      };
      var keystore = createInstance();

      jwk = new JWK.BaseKey(jwk.kty, keystore, jwk, DUMMY_FACTORY.config);

      var promise = keystore.add(jwk);
      assert.ok("function" === typeof promise.then);
      promise = promise.then(function(key) {
        // is a key ...
        assert.ok(JWK.store.KeyStore.isKey(key));
        assert.deepEqual(key.toObject(true), {
          "kty": "DUMMY",
          "kid": "someid",
          "use": "sig",
          "alg": "HS256",
          "pub": new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
        });

        // ... and exists in the keystore
        assert.deepEqual(keystore.all(), [key]);

        return key;
      });

      promise = promise.then(function(key) {
        keystore.remove(key);

        assert.deepEqual(keystore.all(), []);
      });

      return promise;
    });
    it("adds/removes a key as a JWK.Key object", function() {
      var jwk = {
        "kty": "DUMMY",
        "kid": "someid",
        "use": "sig",
        "alg": "HS256",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      };
      var keystore = createInstance();

      jwk = new JWK.BaseKey(jwk.kty, keystore, jwk, DUMMY_FACTORY.config);

      var promise = keystore.add(jwk);
      assert.ok("function" === typeof promise.then);
      promise = promise.then(function(key) {
        // is a key ...
        assert.ok(JWK.store.KeyStore.isKey(key));
        assert.deepEqual(key.toObject(true), {
          "kty": "DUMMY",
          "kid": "someid",
          "use": "sig",
          "alg": "HS256",
          "pub": new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
        });

        // ... and exists in the keystore
        assert.deepEqual(keystore.all(), [key]);

        return key;
      });

      promise = promise.then(function(key) {
        keystore.remove(key);

        assert.deepEqual(keystore.all(), []);
      });

      return promise;
    });

    it("fails with unknown 'kty'", function() {
      var keystore = createInstance();
      var jwk = {
        kty: "BOGUS",
        kid: "someid",
        pub: new Buffer(forge.random.getBytes(16), "binary")
      };

      var promise = keystore.add(jwk);
      promise = promise.then(function() {
        assert.ok(false, "promise unexpectedly resolved");
      }, function(err) {
        assert.equal(err.message, "unsupported key type");
      });

      return promise;
    });
  });

  describe("generation", function() {
    it("generates a key with properties", function() {
      var keystore = createInstance();
      var props = {
        kid: "someid",
        use: "enc"
      };
      var promise = keystore.generate("DUMMY", 128, props);
      promise = promise.then(function(key) {
        assert.strictEqual(key.keystore, keystore);
        assert.equal(key.kty, "DUMMY");
        assert.equal(key.kid, "someid");
        assert.equal(key.get("use"), "enc");
        assert.ok(!!key.get("pub"));
        assert.ok(!!key.get("prv", true));
        assert.deepEqual(keystore.all(), [key]);
      });

      return promise;
    });
    it("generates a key simple", function() {
      var keystore = createInstance();
      var promise = keystore.generate("DUMMY", 128);
      promise = promise.then(function(key) {
        assert.strictEqual(key.keystore, keystore);
        assert.equal(key.kty, "DUMMY");
        assert.equal(typeof key.kid, "string");
        assert.ok(!!key.get("pub"));
        assert.ok(!!key.get("prv", true));
        assert.deepEqual(keystore.all(), [key]);
      });

      return promise;
    });
    it("fails with unknown 'kty'", function() {
      var keystore = createInstance();

      var promise = keystore.generate("BOGUS", 256);
      promise = promise.then(function() {
        assert.ok(false, "promise unexpectedly resolved");
      }, function(err) {
        assert.equal(err.message, "unsupported key type");
      });

      return promise;
    });
  });

  describe("temp", function() {
    var keystore;
    before(function() {
      var jwk = {
        "kty": "DUMMY",
        "kid": "someid",
        "use": "sig",
        "alg": "HS256",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      };
      keystore = createInstance();
      return keystore.add(jwk);
    });
    it("it creates a child keystore", function() {
      var tks = keystore.temp();
      assert.deepEqual(tks.all(), keystore.all());

      var jwk = {
        "kty": "DUMMY",
        "kid": "diffid",
        "use": "enc",
        "alg": "A256GCM",
        "pub": util.base64url.encode(new Buffer("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(new Buffer("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
      };
      var promise = tks.add(jwk);
      promise = promise.then(function(key) {
        assert.strictEqual(tks.get("diffid"), key);
        assert.ok(!keystore.get("diffid"));
      });
      return promise;
    });
  });

  describe("query", function() {
    // TODO: testit!
  });

  describe("export", function() {
    // ensure there's registred key types
    require("../../lib/jwk/rsakey.js");
    require("../../lib/jwk/octkey.js");

    var inst = JWK.store.KeyStore.createKeyStore(),
        keys = [
          {
            "kty": "RSA",
            "kid": "somekey",
            "use": "sig",
            "n": "i8exGrwNz69aIKhpblb7DrouMBJJohuzhGPezA1EWZ8klqNt7kxKhd3fA1MN1Nn9QTIX4NefJxmOwzXhq6qLtfOa7ZnXUS-pWrs3pm9oFOf1qF1DbeEDTaTbkvxlO7AFUs_LR1-wHyztH0O-Rl17WqUUjcoA07QYwHCKm1cP_kE4yCkyT0EPNkreCnwQEs-1xvZkyAo_zLjESN8y_Ck9FTTTAWmuEbUhtE1_QmlCfFaoUsBJ5OJG6eCTmr1MQ47T4flKDq6-PFr4JCFyMrmnungxpsg4lp-s1sUgg5qRUyga6ze854pmAgQKzj61lhs8g7k1J5HR6S0PL7xQl5pW6Q",
            "e": "AQAB",
            "d": "TgcjLjFb5FuWjDR25klXzFjR_7O1tvCPvY-ih3XAeecEnbKNY0DjOOcp3sk2J2OopAQ6oCC9jy4NK5ugZhvF8cQS8B-4unFIsIViA16dU05JK7skMOoy1dz5VYvfVvpjfl7Qsv8PadfCZnmCdfUpLuiIGL5yx7r5NjOcrCplmyApr5KJ53Qk8q76WVbZvH4bxmzoK2sOhzjH_4I4bcdlueeUj6VNZXiReY2VpldsoIgmntEy1z7DMVRjqwvBFLM7yD4P9Dlk3pfHtSMtDMyAsnaco7cAA95t1Yk60Om9RlCf_CjbmempzQ_P6Ned9VJYUvtcadqIE0lhe4Pp4POgAQ",
            "p": "y-7A4AGF8dkUjHKVXmPQ65ymWO2ACP8jR9LVrkRXd0uPXQyJqTa-233H0pqXRuMiTCnbYTr3oz4ePX53SDUsusDtWgGsrzTRozoHQoxA6cjLX-1VcjlgPpW2gzltlQWv7MBK-LaxGwlS3iuc9tuTE2vwvyPWBO3orQIF21ZoDGk",
            "q": "r3fcBfzoik-U1cL_eNb3dFCnnCt3KsBSQj0zgSKhxcdQYXkWrUgx2F0nzN98T7zjBqDcuVtdRVe8JL1HN_J5fqdjNdfCyvT5asS-MccY-fZwMsdcsT1LLLqZDWd6TsMLMpzW_dTkPTWIKWJB27-DFS61mYafvah2HfWxt8ggpoE",
            "dp": "lbOdOJNFrWTKldMjXRfu7Jag8lTeETyhvH7Dx1p5zqPUCN1ETMhYUK3DuxEqjan8qmZrmbN8yAO4lTG6BHKsdCdd1R23kyI15hmZ7Lsih7uTt8Z0XBZMVYT3ZtsIW0XCgAwkvPD3j75Ha7oeToSfMbmiD94RpKq0jBQZEosadEk",
            "dq": "OcG2RrJMyNoRH5ukA96ebUbvJNSZ0RSk_vCuN19y6GsG5k65TChrX9Cp_SHDBWwjPldM0CZmuSB76Yv0GVJS84GdgmeW0r94KdDA2hmy-vRHUi-VLzIBwKNbJbJd6_b_hJVjnwGobw1j2FtjWjXbq-lIFVTe18rPtmTdLqVNOgE",
            "qi": "YYCsHYc8qLJ1aIWnVJ9srXBC3VPWhB98tjOdK-xafhi19TeDL3OxazFV0f0FuxEGOmYeHyF4nh72wK3kRBrcosNQkAlK8oMH3Cg_AnMYehFRmDSKUFjDjXH5bVBfFk72FkmEywEaQgOiYs34P4RAEBdZohh6UTZm0-bajOkVEOE"
          },
          {
            kty: "oct",
            kid: "somevalue",
            k: "SBh6LBt1DBTeyHTvwDgSjg",
            use: "enc",
            alg: "A128GCM"
          }
        ];

    before(function() {
      keys = keys.map(function(k) {
        return inst.add(k);
      });
      return Promise.all(keys).
             then(function(results) {
               keys = results;
             });
    });

    it("toJSON() exports the keys (public fields only)", function() {
      var actual = inst.toJSON();
      var expected = {
        keys: keys.map(function(k) {
          return k.toJSON();
        })
      };
      assert.deepEqual(actual, expected);
    });
    it("toJSON() exports the keys (with private fields)", function() {
      var actual = inst.toJSON(true);
      var expected = {
        keys: keys.map(function(k) {
          return k.toJSON(true);
        })
      };
      assert.deepEqual(actual, expected);
    });
  });

  describe("static", function() {
    // ensure there's a registered key type
    require("../../lib/jwk/octkey.js");

    describe("KeyStore.isKey", function() {
      it("tests for JWK.Key instances", function() {
        var props = {
          kty: "oct",
          kid: "somevalue",
          k: "SBh6LBt1DBTeyHTvwDgSjg",
          use: "enc",
          alg: "A128GCM"
        };
        var ks = createInstance(),
            inst = new JWK.BaseKey("DUMMY", ks, {}, DUMMY_FACTORY.config);

        assert.equal(JWK.store.KeyStore.isKey(inst), true);
        assert.equal(JWK.store.KeyStore.isKey(props), false);
        assert.equal(JWK.store.KeyStore.isKey(42), false);
        assert.equal(JWK.store.KeyStore.isKey("hello"), false);
        assert.equal(JWK.store.KeyStore.isKey(null), false);
        assert.equal(JWK.store.KeyStore.isKey(), false);
      });
    });
    describe("KeyStore.asKey", function() {
      var props = {
        kty: "oct",
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };

      it("returns the provided JWK.Key instance", function() {
        var ks = createInstance(),
            key = new JWK.BaseKey(props.kty, ks, props, DUMMY_FACTORY.config),
            promise = Promise.resolve(key);
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKey(json);
        });
        promise = promise.then(function(jwk) {
          assert.ok(JWK.store.KeyStore.isKey(jwk));
          assert.strictEqual(jwk, key);
        });

        return promise;
      });

      it("coerces JSON Object to JWK.Key instance", function() {
        var promise = Promise.resolve(props);
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKey(json);
        });
        promise = promise.then(function(jwk) {
          assert.ok(JWK.store.KeyStore.isKey(jwk));
        });

        return promise;
      });

      it("coerces JSON String to JWK.Key instance", function() {
        var promise = Promise.resolve(JSON.stringify(props));
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKey(json);
        });
        promise = promise.then(function(jwk) {
          assert.ok(JWK.store.KeyStore.isKey(jwk));
        });

        return promise;
      });

      describe("EC integration", function() {
        var pkcs8 = new Buffer("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkNTFf0EmmwXj1b1Mo+h9ySraek2VhdGGwz48Cm5jF1yhRANCAARZVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkK", "base64"),
            spki = new Buffer("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWVXns1zCDbbGWVnXQRUvT4342FNEzAiTy1tDz5mfhJqzbqR5D8qyjjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==", "base64"),
            pkix = new Buffer("MIICMzCCAdmgAwIBAgIJAMwo6FDPY28LMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE5MzgxMloXDTE2MDkyOTE5MzgxMlowdjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAUBgNVBAMMDWttcy5jaXNjby5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkKo1AwTjAdBgNVHQ4EFgQUNmIbQpQISpglBzdUyLLg5zR3u5swHwYDVR0jBBgwFoAUNmIbQpQISpglBzdUyLLg5zR3u5swDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAvkFO6ok2tadxhXjCCJ99+P1MhQ3FPUav1cs9mdCjkUgIhAKZGQ118RwlQpMX8B1nVsI7wP8c6iGfKwTkRwoKrSFr7", "base64"),
            pem = {
              public: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWVXns1zCDbbGWVnXQRUvT4342FNE\nzAiTy1tDz5mfhJqzbqR5D8qyjjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==\n-----END PUBLIC KEY-----\n",
              private: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkNTFf0EmmwXj1b1M\no+h9ySraek2VhdGGwz48Cm5jF1yhRANCAARZVeezXMINtsZZWddBFS9PjfjYU0TM\nCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkK\n-----END PRIVATE KEY-----\n",
              cert: "-----BEGIN CERTIFICATE-----\nMIICMzCCAdmgAwIBAgIJAMwo6FDPY28LMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYT\nAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQK\nDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1r\nbXMuY2lzY28uY29tMB4XDTE1MDkzMDE5MzgxMloXDTE2MDkyOTE5MzgxMlowdjEL\nMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIx\nHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAU\nBgNVBAMMDWttcy5jaXNjby5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZ\nVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc\n1EPfPPcQYJwsW9iGNKkKo1AwTjAdBgNVHQ4EFgQUNmIbQpQISpglBzdUyLLg5zR3\nu5swHwYDVR0jBBgwFoAUNmIbQpQISpglBzdUyLLg5zR3u5swDAYDVR0TBAUwAwEB\n/zAKBggqhkjOPQQDAgNIADBFAiAvkFO6ok2tadxhXjCCJ99+P1MhQ3FPUav1cs9m\ndCjkUgIhAKZGQ118RwlQpMX8B1nVsI7wP8c6iGfKwTkRwoKrSFr7\n-----END CERTIFICATE-----\n"
            };
        it("coerces PKCS8 String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkcs8, "pkcs8");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces SPKI String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(spki, "spki");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PKIX String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkix, "pkix");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces X509 String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkix, "x509");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PRIVATE KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.private, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PUBLIC KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.public, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces CERTIFICATE PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.cert, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
      });
      describe("RSA integration", function() {
        var pkcs8 = new Buffer("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAECggEAIgtrHmUaQ3uoIikiBevVAdoz4K8zbFk17+UY36xHzDZcGulXDf7lZ0tCmjaU3dXZMlfUjN2kKIYv3RyKPVSHys0qIqLbICiU9LU8+l8N1YJrL7EhqTwV3HZGwaOsxbtdodfXBhDwzY4LNTcWYzn3U8XS4GCEczLS4NCQNIUpq/hb5yOX38WmDl+se8lXwq3F97PU/OLv2N0IhzMmZ4fBqRTWYIvqXQ6Sj//EC5LmEJoB5F+fqvZctt7AMf+mXpKR3Zc87Tq7OK3xrzBlniXo090QXHQ82RDQpC73G6PcCdghu4LwUvBOXoMan0n4oet8Zbwlo+80zGGs8cJGdxBTAQKBgQDlc91zv1G2PXTFPwEX7FPWoqSt+6cCH+/18nsu6nCQwIdVccKlyraLmAViP83dgTcMbcJPetSOjSTKM93NsTBj0YHjDB/ztw6q13hSFL8y3rv6PiNaV0VckVmyh4sXVRovMDDGpex6BI/rSpIIvfUxpmFzBaMJos842Z6c0KATEwKBgQDIjtsF+CMqb0oXsJFaqFyFw0P26jKrsIKoJ0rF1Qmo4/yupULJYygyp36n8ya1braNBOaMwRTkMH5B9QatiRnOQalyKChh3jYhlGRdZF+HZJgxme5izJo338KjhrZ1oNHNc7DgsFbQcehqTu9r9QAJglZ+teqQVFIIQ3XuW7b0oQKBgFCwsVUOF+c1r4XaBUFre4REiBMjJ3Uo1BMy5bz29wUAn9cdfW0eX5mxqVsGwxe9ZCV7x9R5hpxm6GQvXzYBtNm1iK7WybnES2UrBwYeg6qZB5QWHAqeHCdUei29Wt2msOGdWdnR6dpzFkWRYM+wNbTzJNv1RIOT/LmqVgwhldl/AoGADG8G1xzmGThjEIrqyAMOEWDkssccMxazUvd0pEUr3yObQ7yNIm0aTeGicYkaij795Eo8fNdvkyIKgc5OBq4sQmRBvAkPT9n14ykO+9dAMOWkpdaUN93VZcdiir7MSwiYWTNl8Ngd2bhmH0kbgMbkpLJG6H4gt6fymf6MriVTd2ECgYAr9n7K7mOqmQwYQKwqGX6ttx11zSyBXnge6gtpbtsO1sEC0WFLhxNLg2cruQMRlmt8lkef5kgTpo8x192GBFjb9gMGtyO2xygD6rDwMsO3r+dwXDyyaGAOscY8FQBDOrNBUxfZ3G4qx8CkaBTDmQoL7vAlvNHSlkaSX3SmqzkGtA==", "base64"),
            spki = new Buffer("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8KPlrvJEQjm9Q2y7Luqz7iB6nLCxm1xdh8JQYeJtDnsD59Zf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT2SlvShst2aGPP30GA7aUGb7Wteu7krjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKkIUWFM6IMc6axyCKr3xxCrx162YrVCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegkC3IaJWx0j9Few+Uk6mpWH7KUjATEXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo1HyZ7nB6AuhHE6EQues/hwtUFWqaArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa8wIDAQAB", "base64"),
            pkix = new Buffer("MIIDvzCCAqegAwIBAgIJALVU3dROl55XMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE3MDkwNloXDTE2MDkyOTE3MDkwNlowdjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAUBgNVBAMMDWttcy5jaXNjby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAGjUDBOMB0GA1UdDgQWBBTnnpV83nEHQ1f3Q3PN5lX8YbLODTAfBgNVHSMEGDAWgBTnnpV83nEHQ1f3Q3PN5lX8YbLODTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB043leHgz4tKqAt6r8aYoZQIxLG03Nz0WL2YJSltgBcy/q3L6iAZYsJ42SEDfyEgk9UBIi8sfZEqp/VHmX8hqmKJJn0s6GNFxUpVe9MLKpaAEACnOr5rDX9abVIZ2XnhqNcEEeWzyunSVy/zj7Yom3yRiPGLLjics90RsOSTa5GaQli51McmWA+4+UhrY9vPNL4v0DBk4jijslsvN66EgPBsUyc0VcQ7fagDcxrvFEo/TQyGHbNrCZR5oY9Ub2D56AUM+ETciEHFy7ICNU/BLlHY4z6BHOMCENESXAvXyXpxs9IEjYrVa1y58yR7Zy9doZW7v7/y+64NaFuRmlXzXc", "base64"),
            pem = {
              public: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8KPlrvJEQjm9Q2y7Luq\nz7iB6nLCxm1xdh8JQYeJtDnsD59Zf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT\n2SlvShst2aGPP30GA7aUGb7Wteu7krjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKk\nIUWFM6IMc6axyCKr3xxCrx162YrVCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegk\nC3IaJWx0j9Few+Uk6mpWH7KUjATEXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo\n1HyZ7nB6AuhHE6EQues/hwtUFWqaArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa\n8wIDAQAB\n-----END PUBLIC KEY-----",
              private: "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzwo+Wu8kRCOb1\nDbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2\ner9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7Ey\nSlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q\n2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k\n5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx\n2rcXXBrzAgMBAAECggEAIgtrHmUaQ3uoIikiBevVAdoz4K8zbFk17+UY36xHzDZc\nGulXDf7lZ0tCmjaU3dXZMlfUjN2kKIYv3RyKPVSHys0qIqLbICiU9LU8+l8N1YJr\nL7EhqTwV3HZGwaOsxbtdodfXBhDwzY4LNTcWYzn3U8XS4GCEczLS4NCQNIUpq/hb\n5yOX38WmDl+se8lXwq3F97PU/OLv2N0IhzMmZ4fBqRTWYIvqXQ6Sj//EC5LmEJoB\n5F+fqvZctt7AMf+mXpKR3Zc87Tq7OK3xrzBlniXo090QXHQ82RDQpC73G6PcCdgh\nu4LwUvBOXoMan0n4oet8Zbwlo+80zGGs8cJGdxBTAQKBgQDlc91zv1G2PXTFPwEX\n7FPWoqSt+6cCH+/18nsu6nCQwIdVccKlyraLmAViP83dgTcMbcJPetSOjSTKM93N\nsTBj0YHjDB/ztw6q13hSFL8y3rv6PiNaV0VckVmyh4sXVRovMDDGpex6BI/rSpII\nvfUxpmFzBaMJos842Z6c0KATEwKBgQDIjtsF+CMqb0oXsJFaqFyFw0P26jKrsIKo\nJ0rF1Qmo4/yupULJYygyp36n8ya1braNBOaMwRTkMH5B9QatiRnOQalyKChh3jYh\nlGRdZF+HZJgxme5izJo338KjhrZ1oNHNc7DgsFbQcehqTu9r9QAJglZ+teqQVFII\nQ3XuW7b0oQKBgFCwsVUOF+c1r4XaBUFre4REiBMjJ3Uo1BMy5bz29wUAn9cdfW0e\nX5mxqVsGwxe9ZCV7x9R5hpxm6GQvXzYBtNm1iK7WybnES2UrBwYeg6qZB5QWHAqe\nHCdUei29Wt2msOGdWdnR6dpzFkWRYM+wNbTzJNv1RIOT/LmqVgwhldl/AoGADG8G\n1xzmGThjEIrqyAMOEWDkssccMxazUvd0pEUr3yObQ7yNIm0aTeGicYkaij795Eo8\nfNdvkyIKgc5OBq4sQmRBvAkPT9n14ykO+9dAMOWkpdaUN93VZcdiir7MSwiYWTNl\n8Ngd2bhmH0kbgMbkpLJG6H4gt6fymf6MriVTd2ECgYAr9n7K7mOqmQwYQKwqGX6t\ntx11zSyBXnge6gtpbtsO1sEC0WFLhxNLg2cruQMRlmt8lkef5kgTpo8x192GBFjb\n9gMGtyO2xygD6rDwMsO3r+dwXDyyaGAOscY8FQBDOrNBUxfZ3G4qx8CkaBTDmQoL\n7vAlvNHSlkaSX3SmqzkGtA==\n-----END PRIVATE KEY-----",
              cert: "-----BEGIN CERTIFICATE-----\nMIIDvzCCAqegAwIBAgIJALVU3dROl55XMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV\nBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYD\nVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQD\nDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE3MDkwNloXDTE2MDkyOTE3MDkwNlow\ndjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52\nZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcx\nFjAUBgNVBAMMDWttcy5jaXNjby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6x\nuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6\niYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJ\naLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2\nWF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lU\nbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAGjUDBOMB0GA1UdDgQWBBTnnpV8\n3nEHQ1f3Q3PN5lX8YbLODTAfBgNVHSMEGDAWgBTnnpV83nEHQ1f3Q3PN5lX8YbLO\nDTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB043leHgz4tKqAt6r8\naYoZQIxLG03Nz0WL2YJSltgBcy/q3L6iAZYsJ42SEDfyEgk9UBIi8sfZEqp/VHmX\n8hqmKJJn0s6GNFxUpVe9MLKpaAEACnOr5rDX9abVIZ2XnhqNcEEeWzyunSVy/zj7\nYom3yRiPGLLjics90RsOSTa5GaQli51McmWA+4+UhrY9vPNL4v0DBk4jijslsvN6\n6EgPBsUyc0VcQ7fagDcxrvFEo/TQyGHbNrCZR5oY9Ub2D56AUM+ETciEHFy7ICNU\n/BLlHY4z6BHOMCENESXAvXyXpxs9IEjYrVa1y58yR7Zy9doZW7v7/y+64NaFuRml\nXzXc\n-----END CERTIFICATE-----"
            };
        it("coerces PKCS8 String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkcs8, "pkcs8");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces SPKI String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(spki, "spki");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PKIX String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkix, "pkix");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces X509 String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkix, "x509");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PRIVATE KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.private, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PUBLIC KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.public, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces CERTIFICATE PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.cert, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
      });
    });

    describe("KeyStore.isKeyStore", function() {
      it("tests for JWK.KeyStore instances", function() {
        var inst = createInstance();

        assert.equal(JWK.store.KeyStore.isKeyStore(inst), true);
        assert.equal(JWK.store.KeyStore.isKeyStore({}), false);
        assert.equal(JWK.store.KeyStore.isKeyStore(42), false);
        assert.equal(JWK.store.KeyStore.isKeyStore("hello"), false);
        assert.equal(JWK.store.KeyStore.isKeyStore(null), false);
        assert.equal(JWK.store.KeyStore.isKeyStore(), false);
      });
    });
    describe("KeyStore.createKeyStore", function() {
      it("creates an empty KeyStore", function() {
        var keystore = JWK.store.KeyStore.createKeyStore();
        assert.equal(JWK.store.KeyStore.isKeyStore(keystore), true);
        assert.deepEqual(keystore.all(), []);
      });
    });
    describe("KeyStore.asKeyStore", function() {
      var props = {
        keys: [
          {
            kty: "oct",
            kid: "onevalue",
            k: "Lc3EY3_96tfej0F7Afa0TQ",
            use: "enc",
            alg: "A128GCM"
          },
          {
            kty: "oct",
            kid: "twovalue",
            k: "TI3C3LsvhIexA3aYg6B6ZMMIhJjLfmddHa_zMyOkZjU",
            use: "enc",
            alg: "A256GCM"
          }
        ]
      };

      it("coerces a JSON Object to a JWK.KeyStore instance", function() {
        var promise = Promise.resolve(props);
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKeyStore(json);
        });
        promise = promise.then(function(ks) {
          assert.ok(JWK.store.KeyStore.isKeyStore(ks));

          var key;
          key = ks.get("onevalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
          key = ks.get("twovalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
        });
        return promise;
      });
      it("coerces a JSON String (of a JSON Object) to a JWK.KeyStore instance", function() {
        var promise = Promise.resolve(JSON.stringify(props));
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKeyStore(json);
        });
        promise = promise.then(function(ks) {
          assert.ok(JWK.store.KeyStore.isKeyStore(ks));

          var key;
          key = ks.get("onevalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
          key = ks.get("twovalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
        });
        return promise;
      });
      it("coerces a JSON Array to a JWK.KeyStore instance", function() {
        var promise = Promise.resolve(props.keys);
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKeyStore(json);
        });
        promise = promise.then(function(ks) {
          assert.ok(JWK.store.KeyStore.isKeyStore(ks));

          var key;
          key = ks.get("onevalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
          key = ks.get("twovalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
        });
        return promise;
      });
      it("coerces a JSON String (of a JSON Array) to a JWK.KeyStore instance", function() {
        var promise = Promise.resolve(JSON.stringify(props.keys));
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKeyStore(json);
        });
        promise = promise.then(function(ks) {
          assert.ok(JWK.store.KeyStore.isKeyStore(ks));

          var key;
          key = ks.get("onevalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
          key = ks.get("twovalue");
          assert.ok(JWK.store.KeyStore.isKey(key));
        });
        return promise;
      });
      it("returns the provided JWK.KeyStore instance", function() {
        var inst = createInstance(),
            promise = Promise.resolve(inst);
        promise = promise.then(function(json) {
          return JWK.store.KeyStore.asKeyStore(json);
        });
        promise = promise.then(function(ks) {
          assert.ok(JWK.store.KeyStore.isKeyStore(ks));
          assert.strictEqual(ks, inst);
        });
        return promise;
      });
    });
  });
});
