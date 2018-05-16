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
      pub: Buffer.from(forge.random.getBytes(size / 8), "binary"),
      prv: Buffer.from(forge.random.getBytes(size / 8), "binary")
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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
          "pub": Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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
          "pub": Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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
          "pub": Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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
          "pub": Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
          "prv": Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex")
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
        pub: Buffer.from(forge.random.getBytes(16), "binary")
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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
        "pub": util.base64url.encode(Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5", "hex")),
        "prv": util.base64url.encode(Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex"))
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

    it("handles (albeit off-spec) number kids", function() {
      var promise = JWK.store.KeyStore.asKeyStore({
        keys: [
          {
             kty: 'RSA',
             alg: 'RS256',
             use: 'sig',
             n: 'zi9ox5mVK1nS6rASj5VwTqsozmyoHcqOuf2LLvuNzijPx7ybASzUerP-QZCYL3EC66TtmO2T2fxEyfrK0r7OpsJ3QYlZZ4rHm7s_mFc9upxjnTZ-ElJJsAxWhuBZyZTpzfXT7lTm4QN0QZgy3ydmv4W4RFh2tzAZ4wKc4ruoI-SIVSiZZZ_R3-zhu6zu2JfRc6Vt6MapLfgNtaVuzKWeuCC-42-4vngf2TYqJLlRvrywNJ1qtf-dUpB5UutJUIPBeDrVmoJPC7H8cdbOxSV3b4y8cvn0aQQouO3vQGyNg-LA0D-NGuSW-nEOyfuUR0skcUh6VIhEpcw8iF8nJ1X7yQ',
             e: 'AQAB',
             kid: 1
           }
        ]
      });

      promise = promise.then(function (keystore) {
        assert.ok(keystore.get({ kid: 1 }));
        assert.equal(keystore.all({ kid: 1 }).length, 1);
      });

      return promise;
    });
  });

  describe("export", function() {
    // ensure there's registred key types
    require("../../lib/jwk/rsakey.js");
    require("../../lib/jwk/octkey.js");

    var inst = JWK.store.KeyStore.createKeyStore(),
        keys = [
          {
            kty: "oct",
            kid: "somevalue",
            k: "SBh6LBt1DBTeyHTvwDgSjg",
            use: "enc",
            alg: "A128GCM"
          },
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
      // TODO: make this test less sensitive to ordering
      var actual = inst.toJSON();
      var expected = {
        keys: keys.map(function(k) {
          return k.toJSON();
        })
      };
      assert.deepEqual(actual, expected);
    });
    it("toJSON() exports the keys (with private fields)", function() {
      // TODO: make this test less sensitive to ordering
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
    describe("KeyStore.createKey", function() {
      it("creates a new Key", function() {
        var p;
        p = JWK.store.KeyStore.createKey("oct", 256);
        p = p.then(function (result) {
          assert.ok(JWK.store.KeyStore.isKey(result));
          assert.strictEqual(result.kty, "oct");
          assert.strictEqual(result.length, 256);
        });
        return p;
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
        // ensure EC is registered
        require("../../lib/jwk/eckey.js");

        var rawPrivate = Buffer.from("MHcCAQEEIJDUxX9BJpsF49W9TKPofckq2npNlYXRhsM+PApuYxdcoAoGCCqGSM49AwEHoUQDQgAEWVXns1zCDbbGWVnXQRUvT4342FNEzAiTy1tDz5mfhJqzbqR5D8qyjjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==", "base64"),
            pkcs8 = Buffer.from("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkNTFf0EmmwXj1b1Mo+h9ySraek2VhdGGwz48Cm5jF1yhRANCAARZVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkK", "base64"),
            spki = Buffer.from("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWVXns1zCDbbGWVnXQRUvT4342FNEzAiTy1tDz5mfhJqzbqR5D8qyjjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==", "base64"),
            pkix = Buffer.from("MIICMzCCAdmgAwIBAgIJAMwo6FDPY28LMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE5MzgxMloXDTE2MDkyOTE5MzgxMlowdjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAUBgNVBAMMDWttcy5jaXNjby5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkKo1AwTjAdBgNVHQ4EFgQUNmIbQpQISpglBzdUyLLg5zR3u5swHwYDVR0jBBgwFoAUNmIbQpQISpglBzdUyLLg5zR3u5swDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAvkFO6ok2tadxhXjCCJ99+P1MhQ3FPUav1cs9mdCjkUgIhAKZGQ118RwlQpMX8B1nVsI7wP8c6iGfKwTkRwoKrSFr7", "base64"),
            pem = {
              rawPrivateParams: "-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJDUxX9BJpsF49W9TKPofckq2npNlYXRhsM+PApuYxdcoAoGCCqGSM49\nAwEHoUQDQgAEWVXns1zCDbbGWVnXQRUvT4342FNEzAiTy1tDz5mfhJqzbqR5D8qy\njjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==\n-----END EC PRIVATE KEY-----\n",
              rawPrivate: "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIJDUxX9BJpsF49W9TKPofckq2npNlYXRhsM+PApuYxdcoAoGCCqGSM49\nAwEHoUQDQgAEWVXns1zCDbbGWVnXQRUvT4342FNEzAiTy1tDz5mfhJqzbqR5D8qy\njjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==\n-----END EC PRIVATE KEY-----\n",
              spki: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWVXns1zCDbbGWVnXQRUvT4342FNE\nzAiTy1tDz5mfhJqzbqR5D8qyjjBPkCnLhLn6HNRD3zz3EGCcLFvYhjSpCg==\n-----END PUBLIC KEY-----\n",
              pkcs8: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgkNTFf0EmmwXj1b1M\no+h9ySraek2VhdGGwz48Cm5jF1yhRANCAARZVeezXMINtsZZWddBFS9PjfjYU0TM\nCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc1EPfPPcQYJwsW9iGNKkK\n-----END PRIVATE KEY-----\n",
              cert: "-----BEGIN CERTIFICATE-----\nMIICMzCCAdmgAwIBAgIJAMwo6FDPY28LMAoGCCqGSM49BAMCMHYxCzAJBgNVBAYT\nAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQK\nDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1r\nbXMuY2lzY28uY29tMB4XDTE1MDkzMDE5MzgxMloXDTE2MDkyOTE5MzgxMlowdjEL\nMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIx\nHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAU\nBgNVBAMMDWttcy5jaXNjby5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZ\nVeezXMINtsZZWddBFS9PjfjYU0TMCJPLW0PPmZ+EmrNupHkPyrKOME+QKcuEufoc\n1EPfPPcQYJwsW9iGNKkKo1AwTjAdBgNVHQ4EFgQUNmIbQpQISpglBzdUyLLg5zR3\nu5swHwYDVR0jBBgwFoAUNmIbQpQISpglBzdUyLLg5zR3u5swDAYDVR0TBAUwAwEB\n/zAKBggqhkjOPQQDAgNIADBFAiAvkFO6ok2tadxhXjCCJ99+P1MhQ3FPUav1cs9m\ndCjkUgIhAKZGQ118RwlQpMX8B1nVsI7wP8c6iGfKwTkRwoKrSFr7\n-----END CERTIFICATE-----\n"
            };
        it("coerces Private String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(rawPrivate, "private");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
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
        it("coerces (raw) PRIVATE KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.rawPrivate, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
            return jwk.toPEM(true);
          });
          promise = promise.then(function(pem) {
            assert.match(pem, /^-----BEGIN EC PRIVATE KEY-----\r\n/);
            assert.match(pem, /\r\n-----END EC PRIVATE KEY-----\r\n$/);
          });

          return promise;
        });
        it("coerces (raw) PRIVATE KEY PEM (with EC PARAMETERS) String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.rawPrivateParams, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces (PKCS8) PRIVATE KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.pkcs8, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces (SPKI) PUBLIC KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.spki, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
            return jwk.toPEM(false);
          });
          promise = promise.then(function(pem) {
            assert.match(pem, /^-----BEGIN PUBLIC KEY-----\r\n/);
            assert.match(pem, /\r\n-----END PUBLIC KEY-----\r\n$/);
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

        var testCerts = [
          {
            crv: "P-256",
            length: 256,
            pem: "-----BEGIN CERTIFICATE-----\nMIIB0TCCAXegAwIBAgIJAOIa9y5lvLCuMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\naXRzIFB0eSBMdGQwHhcNMTUxMDI4MTgyMzM2WhcNMTUxMTI3MTgyMzM2WjBFMQsw\nCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\nZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGeQ2\ngjyuKuKzY46RlXq3YFm3+1I1dh5qJyjT0JHL1cbJcWCkX1hbwGcHLuL1Ta6qsVLX\nwfQa55T39lqIIds7NqNQME4wHQYDVR0OBBYEFF42p46deJNeby5P4+Ek91GPYXt7\nMB8GA1UdIwQYMBaAFF42p46deJNeby5P4+Ek91GPYXt7MAwGA1UdEwQFMAMBAf8w\nCgYIKoZIzj0EAwIDSAAwRQIgK8sUDXrdzwAm8tEbV6u0VGjxaEu20B8bhGgxTMKA\nvpECIQDkPcth66+tl1jQ4ETvhU3Ywx0rToQIEmbJRn5Yo99z+A==\n-----END CERTIFICATE-----",
            x5t: "3lbJdwihFwh2KqAENvtZHpgGYps",
            x: "19e436823cae2ae2b3638e91957ab76059b7fb5235761e6a2728d3d091cbd5c6",
            y: "c97160a45f585bc067072ee2f54daeaab152d7c1f41ae794f7f65a8821db3b36"
          },
          {
            crv: "P-384",
            length: 384,
            pem: "-----BEGIN CERTIFICATE-----\nMIICDTCCAZSgAwIBAgIJAKYjYGW6WkVkMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\naXRzIFB0eSBMdGQwHhcNMTUxMDI4MTgyMzM5WhcNMTUxMTI3MTgyMzM5WjBFMQsw\nCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\nZXQgV2lkZ2l0cyBQdHkgTHRkMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4clzVD3q\nKFW91bJ61je+U6+35jWR7QK/HfUm6Q7ZO93BBBGsNnuKbe8VPGke2sL3ci4j3bxy\nvJ7DWUhuFGykOoJp7c8a/mYHWPiXPIHJNuu4lWWq0NzvQCAiE+FAy+YDo1AwTjAd\nBgNVHQ4EFgQUTh5igdnB8pJH4jzPg6ycT/7nL6QwHwYDVR0jBBgwFoAUTh5igdnB\n8pJH4jzPg6ycT/7nL6QwDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNnADBkAjA/\nJjs9THbvH9O7+p4VrLdIqlicWBcBlv8Rw7Cuytj0b4yiRcbhf6y8WMoFol+W8pEC\nMF7A7y4MEbNYOmxeCGrZtNZzZAzWnovTmAS18T19HWfHGprc3AzcLK2AnJ1Myc+M\nsg==\n-----END CERTIFICATE-----",
            x5t: "suAvZH7y9LNqox5Y9Lt-QSBQwwg",
            x: "e1c973543dea2855bdd5b27ad637be53afb7e63591ed02bf1df526e90ed93bddc10411ac367b8a6def153c691edac2f7",
            y: "722e23ddbc72bc9ec359486e146ca43a8269edcf1afe660758f8973c81c936ebb89565aad0dcef40202213e140cbe603"
          },
          {
            crv: "P-521",
            length: 521,
            pem: "-----BEGIN CERTIFICATE-----\nMIICWTCCAbqgAwIBAgIJAJjQ+ASg4bQCMAoGCCqGSM49BAMCMEUxCzAJBgNVBAYT\nAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRn\naXRzIFB0eSBMdGQwHhcNMTUxMDI4MTgyMzQxWhcNMTUxMTI3MTgyMzQxWjBFMQsw\nCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJu\nZXQgV2lkZ2l0cyBQdHkgTHRkMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB23Gr\n27hPSl4XKyPkaO4AehUSU55WznhyAfY75ZefZ7H+R4bx+pJEBgKBN31BgSYH9iUF\n5uUG588t+O+ig7D/MWAB8LnUkxihpV6qVW5C7zrJTBKX5jg8VkQHu7vpUJmqppbj\nx2HEGqWVwdQlj5vQiX9FYGUnn7SR+PC4LVf1wi8SzdSjUDBOMB0GA1UdDgQWBBS/\n+T5g2xPKTvpS7DF7RM+GPruDDTAfBgNVHSMEGDAWgBS/+T5g2xPKTvpS7DF7RM+G\nPruDDTAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA4GMADCBiAJCAdQx+xviVWP2\nZMabRMOFctOdBl4RxKgahAsiL34lGMkvz8pjvQhoofPmdKk8roQxOWQHKLMIr5k8\nEQW99RyMMxUAAkIBkF5T9y2/SbpNcHMI/9k9rYXYc+7Ix/7l8sJIdJjU5nImUY4J\nYOahtIojKOX6C7CAzzGSaOhdqRfTC/vQ7tMNEz8=\n-----END CERTIFICATE-----",
            x5t: "bdfIxLQ6r5IgLczVVRC0c_elBhY",
            x: "01db71abdbb84f4a5e172b23e468ee007a1512539e56ce787201f63be5979f67b1fe4786f1fa9244060281377d41812607f62505e6e506e7cf2df8efa283b0ff3160",
            y: "01f0b9d49318a1a55eaa556e42ef3ac94c1297e6383c564407bbbbe95099aaa696e3c761c41aa595c1d4258f9bd0897f456065279fb491f8f0b82d57f5c22f12cdd4"
          }

        ];

        testCerts.map(function(entry){
          it("coerces a 'EC:" + entry.crv + "' CERTIFICATE PEM String to JWK.Key instance and calculates a proper x5t", function(){
            var promise = Promise.resolve();
            promise = promise.then(function(){
              var keystore = JWK.store.KeyStore.createKeyStore();
              return keystore.add(entry.pem, "pem");
            });

            promise = promise.then(function(key){
              assert.equal(key.kty, "EC");
              assert.equal(key.length, entry.length);
              ["crv", "x", "y", "x5t"].forEach(function(prop){
                assert.equal(key.has(prop), true, "key.has(\"" + prop + "\")");
                assert.isNotNull(key.get(prop));
                assert.equal(key.get(prop).toString("hex"), entry[prop], "key.get(\"" + prop + "\")");
              });
            });

            return promise;
          });
        });
      });
      describe("RSA integration", function() {
        // ensure RSA is registered
        require("../../lib/jwk/rsakey.js");

        var rawPrivate = Buffer.from("MIIEogIBAAKCAQEAs8KPlrvJEQjm9Q2y7Luqz7iB6nLCxm1xdh8JQYeJtDnsD59Zf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT2SlvShst2aGPP30GA7aUGb7Wteu7krjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKkIUWFM6IMc6axyCKr3xxCrx162YrVCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegkC3IaJWx0j9Few+Uk6mpWH7KUjATEXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo1HyZ7nB6AuhHE6EQues/hwtUFWqaArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa8wIDAQABAoIBACILax5lGkN7qCIpIgXr1QHaM+CvM2xZNe/lGN+sR8w2XBrpVw3+5WdLQpo2lN3V2TJX1IzdpCiGL90cij1Uh8rNKiKi2yAolPS1PPpfDdWCay+xIak8Fdx2RsGjrMW7XaHX1wYQ8M2OCzU3FmM591PF0uBghHMy0uDQkDSFKav4W+cjl9/Fpg5frHvJV8Ktxfez1Pzi79jdCIczJmeHwakU1mCL6l0Oko//xAuS5hCaAeRfn6r2XLbewDH/pl6Skd2XPO06uzit8a8wZZ4l6NPdEFx0PNkQ0KQu9xuj3AnYIbuC8FLwTl6DGp9J+KHrfGW8JaPvNMxhrPHCRncQUwECgYEA5XPdc79Rtj10xT8BF+xT1qKkrfunAh/v9fJ7LupwkMCHVXHCpcq2i5gFYj/N3YE3DG3CT3rUjo0kyjPdzbEwY9GB4wwf87cOqtd4UhS/Mt67+j4jWldFXJFZsoeLF1UaLzAwxqXsegSP60qSCL31MaZhcwWjCaLPONmenNCgExMCgYEAyI7bBfgjKm9KF7CRWqhchcND9uoyq7CCqCdKxdUJqOP8rqVCyWMoMqd+p/MmtW62jQTmjMEU5DB+QfUGrYkZzkGpcigoYd42IZRkXWRfh2SYMZnuYsyaN9/Co4a2daDRzXOw4LBW0HHoak7va/UACYJWfrXqkFRSCEN17lu29KECgYBQsLFVDhfnNa+F2gVBa3uERIgTIyd1KNQTMuW89vcFAJ/XHX1tHl+ZsalbBsMXvWQle8fUeYacZuhkL182AbTZtYiu1sm5xEtlKwcGHoOqmQeUFhwKnhwnVHotvVrdprDhnVnZ0enacxZFkWDPsDW08yTb9USDk/y5qlYMIZXZfwKBgAxvBtcc5hk4YxCK6sgDDhFg5LLHHDMWs1L3dKRFK98jm0O8jSJtGk3honGJGoo+/eRKPHzXb5MiCoHOTgauLEJkQbwJD0/Z9eMpDvvXQDDlpKXWlDfd1WXHYoq+zEsImFkzZfDYHdm4Zh9JG4DG5KSyRuh+ILen8pn+jK4lU3dhAoGAK/Z+yu5jqpkMGECsKhl+rbcddc0sgV54HuoLaW7bDtbBAtFhS4cTS4NnK7kDEZZrfJZHn+ZIE6aPMdfdhgRY2/YDBrcjtscoA+qw8DLDt6/ncFw8smhgDrHGPBUAQzqzQVMX2dxuKsfApGgUw5kKC+7wJbzR0pZGkl90pqs5BrQ=", "base64"),
            pkcs8 = Buffer.from("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAECggEAIgtrHmUaQ3uoIikiBevVAdoz4K8zbFk17+UY36xHzDZcGulXDf7lZ0tCmjaU3dXZMlfUjN2kKIYv3RyKPVSHys0qIqLbICiU9LU8+l8N1YJrL7EhqTwV3HZGwaOsxbtdodfXBhDwzY4LNTcWYzn3U8XS4GCEczLS4NCQNIUpq/hb5yOX38WmDl+se8lXwq3F97PU/OLv2N0IhzMmZ4fBqRTWYIvqXQ6Sj//EC5LmEJoB5F+fqvZctt7AMf+mXpKR3Zc87Tq7OK3xrzBlniXo090QXHQ82RDQpC73G6PcCdghu4LwUvBOXoMan0n4oet8Zbwlo+80zGGs8cJGdxBTAQKBgQDlc91zv1G2PXTFPwEX7FPWoqSt+6cCH+/18nsu6nCQwIdVccKlyraLmAViP83dgTcMbcJPetSOjSTKM93NsTBj0YHjDB/ztw6q13hSFL8y3rv6PiNaV0VckVmyh4sXVRovMDDGpex6BI/rSpIIvfUxpmFzBaMJos842Z6c0KATEwKBgQDIjtsF+CMqb0oXsJFaqFyFw0P26jKrsIKoJ0rF1Qmo4/yupULJYygyp36n8ya1braNBOaMwRTkMH5B9QatiRnOQalyKChh3jYhlGRdZF+HZJgxme5izJo338KjhrZ1oNHNc7DgsFbQcehqTu9r9QAJglZ+teqQVFIIQ3XuW7b0oQKBgFCwsVUOF+c1r4XaBUFre4REiBMjJ3Uo1BMy5bz29wUAn9cdfW0eX5mxqVsGwxe9ZCV7x9R5hpxm6GQvXzYBtNm1iK7WybnES2UrBwYeg6qZB5QWHAqeHCdUei29Wt2msOGdWdnR6dpzFkWRYM+wNbTzJNv1RIOT/LmqVgwhldl/AoGADG8G1xzmGThjEIrqyAMOEWDkssccMxazUvd0pEUr3yObQ7yNIm0aTeGicYkaij795Eo8fNdvkyIKgc5OBq4sQmRBvAkPT9n14ykO+9dAMOWkpdaUN93VZcdiir7MSwiYWTNl8Ngd2bhmH0kbgMbkpLJG6H4gt6fymf6MriVTd2ECgYAr9n7K7mOqmQwYQKwqGX6ttx11zSyBXnge6gtpbtsO1sEC0WFLhxNLg2cruQMRlmt8lkef5kgTpo8x192GBFjb9gMGtyO2xygD6rDwMsO3r+dwXDyyaGAOscY8FQBDOrNBUxfZ3G4qx8CkaBTDmQoL7vAlvNHSlkaSX3SmqzkGtA==", "base64"),
            spki = Buffer.from("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8KPlrvJEQjm9Q2y7Luqz7iB6nLCxm1xdh8JQYeJtDnsD59Zf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT2SlvShst2aGPP30GA7aUGb7Wteu7krjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKkIUWFM6IMc6axyCKr3xxCrx162YrVCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegkC3IaJWx0j9Few+Uk6mpWH7KUjATEXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo1HyZ7nB6AuhHE6EQues/hwtUFWqaArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa8wIDAQAB", "base64"),
            pkix = Buffer.from("MIIDvzCCAqegAwIBAgIJALVU3dROl55XMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYDVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQDDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE3MDkwNloXDTE2MDkyOTE3MDkwNlowdjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52ZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcxFjAUBgNVBAMMDWttcy5jaXNjby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAGjUDBOMB0GA1UdDgQWBBTnnpV83nEHQ1f3Q3PN5lX8YbLODTAfBgNVHSMEGDAWgBTnnpV83nEHQ1f3Q3PN5lX8YbLODTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB043leHgz4tKqAt6r8aYoZQIxLG03Nz0WL2YJSltgBcy/q3L6iAZYsJ42SEDfyEgk9UBIi8sfZEqp/VHmX8hqmKJJn0s6GNFxUpVe9MLKpaAEACnOr5rDX9abVIZ2XnhqNcEEeWzyunSVy/zj7Yom3yRiPGLLjics90RsOSTa5GaQli51McmWA+4+UhrY9vPNL4v0DBk4jijslsvN66EgPBsUyc0VcQ7fagDcxrvFEo/TQyGHbNrCZR5oY9Ub2D56AUM+ETciEHFy7ICNU/BLlHY4z6BHOMCENESXAvXyXpxs9IEjYrVa1y58yR7Zy9doZW7v7/y+64NaFuRmlXzXc", "base64"),
            pem = {
              rawPrivate: "-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAs8KPlrvJEQjm9Q2y7Luqz7iB6nLCxm1xdh8JQYeJtDnsD59Z\nf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT2SlvShst2aGPP30GA7aUGb7Wteu7\nkrjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKkIUWFM6IMc6axyCKr3xxCrx162YrV\nCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegkC3IaJWx0j9Few+Uk6mpWH7KUjATE\nXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo1HyZ7nB6AuhHE6EQues/hwtUFWqa\nArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa8wIDAQABAoIBACILax5lGkN7qCIp\nIgXr1QHaM+CvM2xZNe/lGN+sR8w2XBrpVw3+5WdLQpo2lN3V2TJX1IzdpCiGL90c\nij1Uh8rNKiKi2yAolPS1PPpfDdWCay+xIak8Fdx2RsGjrMW7XaHX1wYQ8M2OCzU3\nFmM591PF0uBghHMy0uDQkDSFKav4W+cjl9/Fpg5frHvJV8Ktxfez1Pzi79jdCIcz\nJmeHwakU1mCL6l0Oko//xAuS5hCaAeRfn6r2XLbewDH/pl6Skd2XPO06uzit8a8w\nZZ4l6NPdEFx0PNkQ0KQu9xuj3AnYIbuC8FLwTl6DGp9J+KHrfGW8JaPvNMxhrPHC\nRncQUwECgYEA5XPdc79Rtj10xT8BF+xT1qKkrfunAh/v9fJ7LupwkMCHVXHCpcq2\ni5gFYj/N3YE3DG3CT3rUjo0kyjPdzbEwY9GB4wwf87cOqtd4UhS/Mt67+j4jWldF\nXJFZsoeLF1UaLzAwxqXsegSP60qSCL31MaZhcwWjCaLPONmenNCgExMCgYEAyI7b\nBfgjKm9KF7CRWqhchcND9uoyq7CCqCdKxdUJqOP8rqVCyWMoMqd+p/MmtW62jQTm\njMEU5DB+QfUGrYkZzkGpcigoYd42IZRkXWRfh2SYMZnuYsyaN9/Co4a2daDRzXOw\n4LBW0HHoak7va/UACYJWfrXqkFRSCEN17lu29KECgYBQsLFVDhfnNa+F2gVBa3uE\nRIgTIyd1KNQTMuW89vcFAJ/XHX1tHl+ZsalbBsMXvWQle8fUeYacZuhkL182AbTZ\ntYiu1sm5xEtlKwcGHoOqmQeUFhwKnhwnVHotvVrdprDhnVnZ0enacxZFkWDPsDW0\n8yTb9USDk/y5qlYMIZXZfwKBgAxvBtcc5hk4YxCK6sgDDhFg5LLHHDMWs1L3dKRF\nK98jm0O8jSJtGk3honGJGoo+/eRKPHzXb5MiCoHOTgauLEJkQbwJD0/Z9eMpDvvX\nQDDlpKXWlDfd1WXHYoq+zEsImFkzZfDYHdm4Zh9JG4DG5KSyRuh+ILen8pn+jK4l\nU3dhAoGAK/Z+yu5jqpkMGECsKhl+rbcddc0sgV54HuoLaW7bDtbBAtFhS4cTS4Nn\nK7kDEZZrfJZHn+ZIE6aPMdfdhgRY2/YDBrcjtscoA+qw8DLDt6/ncFw8smhgDrHG\nPBUAQzqzQVMX2dxuKsfApGgUw5kKC+7wJbzR0pZGkl90pqs5BrQ=\n-----END RSA PRIVATE KEY-----",
              spki: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs8KPlrvJEQjm9Q2y7Luq\nz7iB6nLCxm1xdh8JQYeJtDnsD59Zf+qesbhtrIiaM93TH552ErC845Xpdnq/cMDT\n2SlvShst2aGPP30GA7aUGb7Wteu7krjyuomDQc2kScIxm6B7YMXQSJOxMkpTNWKk\nIUWFM6IMc6axyCKr3xxCrx162YrVCCx6yWi1aCS2UH4MfDiaBcbNKRJeKtgjqegk\nC3IaJWx0j9Few+Uk6mpWH7KUjATEXLTjdlhdcECkcQHZ96MCy6obaGmPZOR1CFTo\n1HyZ7nB6AuhHE6EQues/hwtUFWqaArPZVG13uMklvlhx4dyPzkxbwFFhMdq3F1wa\n8wIDAQAB\n-----END PUBLIC KEY-----",
              pkcs8: "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCzwo+Wu8kRCOb1\nDbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6xuG2siJoz3dMfnnYSsLzjlel2\ner9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6iYNBzaRJwjGboHtgxdBIk7Ey\nSlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJaLVoJLZQfgx8OJoFxs0pEl4q\n2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2WF1wQKRxAdn3owLLqhtoaY9k\n5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lUbXe4ySW+WHHh3I/OTFvAUWEx\n2rcXXBrzAgMBAAECggEAIgtrHmUaQ3uoIikiBevVAdoz4K8zbFk17+UY36xHzDZc\nGulXDf7lZ0tCmjaU3dXZMlfUjN2kKIYv3RyKPVSHys0qIqLbICiU9LU8+l8N1YJr\nL7EhqTwV3HZGwaOsxbtdodfXBhDwzY4LNTcWYzn3U8XS4GCEczLS4NCQNIUpq/hb\n5yOX38WmDl+se8lXwq3F97PU/OLv2N0IhzMmZ4fBqRTWYIvqXQ6Sj//EC5LmEJoB\n5F+fqvZctt7AMf+mXpKR3Zc87Tq7OK3xrzBlniXo090QXHQ82RDQpC73G6PcCdgh\nu4LwUvBOXoMan0n4oet8Zbwlo+80zGGs8cJGdxBTAQKBgQDlc91zv1G2PXTFPwEX\n7FPWoqSt+6cCH+/18nsu6nCQwIdVccKlyraLmAViP83dgTcMbcJPetSOjSTKM93N\nsTBj0YHjDB/ztw6q13hSFL8y3rv6PiNaV0VckVmyh4sXVRovMDDGpex6BI/rSpII\nvfUxpmFzBaMJos842Z6c0KATEwKBgQDIjtsF+CMqb0oXsJFaqFyFw0P26jKrsIKo\nJ0rF1Qmo4/yupULJYygyp36n8ya1braNBOaMwRTkMH5B9QatiRnOQalyKChh3jYh\nlGRdZF+HZJgxme5izJo338KjhrZ1oNHNc7DgsFbQcehqTu9r9QAJglZ+teqQVFII\nQ3XuW7b0oQKBgFCwsVUOF+c1r4XaBUFre4REiBMjJ3Uo1BMy5bz29wUAn9cdfW0e\nX5mxqVsGwxe9ZCV7x9R5hpxm6GQvXzYBtNm1iK7WybnES2UrBwYeg6qZB5QWHAqe\nHCdUei29Wt2msOGdWdnR6dpzFkWRYM+wNbTzJNv1RIOT/LmqVgwhldl/AoGADG8G\n1xzmGThjEIrqyAMOEWDkssccMxazUvd0pEUr3yObQ7yNIm0aTeGicYkaij795Eo8\nfNdvkyIKgc5OBq4sQmRBvAkPT9n14ykO+9dAMOWkpdaUN93VZcdiir7MSwiYWTNl\n8Ngd2bhmH0kbgMbkpLJG6H4gt6fymf6MriVTd2ECgYAr9n7K7mOqmQwYQKwqGX6t\ntx11zSyBXnge6gtpbtsO1sEC0WFLhxNLg2cruQMRlmt8lkef5kgTpo8x192GBFjb\n9gMGtyO2xygD6rDwMsO3r+dwXDyyaGAOscY8FQBDOrNBUxfZ3G4qx8CkaBTDmQoL\n7vAlvNHSlkaSX3SmqzkGtA==\n-----END PRIVATE KEY-----",
              cert: "-----BEGIN CERTIFICATE-----\nMIIDvzCCAqegAwIBAgIJALVU3dROl55XMA0GCSqGSIb3DQEBCwUAMHYxCzAJBgNV\nBAYTAlVTMREwDwYDVQQIDAhDb2xvcmFkbzEPMA0GA1UEBwwGRGVudmVyMRwwGgYD\nVQQKDBNDaXNjbyBTeXN0ZW1zLCBJbmMuMQ0wCwYDVQQLDARDQ1RHMRYwFAYDVQQD\nDA1rbXMuY2lzY28uY29tMB4XDTE1MDkzMDE3MDkwNloXDTE2MDkyOTE3MDkwNlow\ndjELMAkGA1UEBhMCVVMxETAPBgNVBAgMCENvbG9yYWRvMQ8wDQYDVQQHDAZEZW52\nZXIxHDAaBgNVBAoME0Npc2NvIFN5c3RlbXMsIEluYy4xDTALBgNVBAsMBENDVEcx\nFjAUBgNVBAMMDWttcy5jaXNjby5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQCzwo+Wu8kRCOb1DbLsu6rPuIHqcsLGbXF2HwlBh4m0OewPn1l/6p6x\nuG2siJoz3dMfnnYSsLzjlel2er9wwNPZKW9KGy3ZoY8/fQYDtpQZvta167uSuPK6\niYNBzaRJwjGboHtgxdBIk7EySlM1YqQhRYUzogxzprHIIqvfHEKvHXrZitUILHrJ\naLVoJLZQfgx8OJoFxs0pEl4q2COp6CQLcholbHSP0V7D5STqalYfspSMBMRctON2\nWF1wQKRxAdn3owLLqhtoaY9k5HUIVOjUfJnucHoC6EcToRC56z+HC1QVapoCs9lU\nbXe4ySW+WHHh3I/OTFvAUWEx2rcXXBrzAgMBAAGjUDBOMB0GA1UdDgQWBBTnnpV8\n3nEHQ1f3Q3PN5lX8YbLODTAfBgNVHSMEGDAWgBTnnpV83nEHQ1f3Q3PN5lX8YbLO\nDTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQB043leHgz4tKqAt6r8\naYoZQIxLG03Nz0WL2YJSltgBcy/q3L6iAZYsJ42SEDfyEgk9UBIi8sfZEqp/VHmX\n8hqmKJJn0s6GNFxUpVe9MLKpaAEACnOr5rDX9abVIZ2XnhqNcEEeWzyunSVy/zj7\nYom3yRiPGLLjics90RsOSTa5GaQli51McmWA+4+UhrY9vPNL4v0DBk4jijslsvN6\n6EgPBsUyc0VcQ7fagDcxrvFEo/TQyGHbNrCZR5oY9Ub2D56AUM+ETciEHFy7ICNU\n/BLlHY4z6BHOMCENESXAvXyXpxs9IEjYrVa1y58yR7Zy9doZW7v7/y+64NaFuRml\nXzXc\n-----END CERTIFICATE-----"
            };
        it("coerces private String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(rawPrivate, "private");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces PKCS8 String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pkcs8, "pkcs8");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces public String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(spki, "public");
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
        it("coerces (raw) PRIVATE KEY PEM String to JWK.Key istance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.rawPrivate, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
            return jwk.toPEM(true);
          });
          promise = promise.then(function(pem) {
            assert.match(pem, /^-----BEGIN RSA PRIVATE KEY-----\r\n/);
            assert.match(pem, /\r\n-----END RSA PRIVATE KEY-----\r\n$/);
          });

          return promise;
        });
        it("coerces (PKCS8) PRIVATE KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.pkcs8, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
          });

          return promise;
        });
        it("coerces (SPKI) PUBLIC KEY PEM String to JWK.Key instance", function() {
          var promise = JWK.store.KeyStore.asKey(pem.spki, "pem");
          promise = promise.then(function(jwk) {
            assert.ok(JWK.store.KeyStore.asKey(jwk));
            return jwk.toPEM(false);
          });
          promise = promise.then(function(pem) {
            assert.match(pem, /^-----BEGIN PUBLIC KEY-----\r\n/);
            assert.match(pem, /\r\n-----END PUBLIC KEY-----\r\n$/);
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

        var testCerts = [
          {
            length: 1024,
            pem: "-----BEGIN CERTIFICATE-----\nMIICWDCCAcGgAwIBAgIJANGa4MfB9TSKMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMTUxMDI4MTQxMzI1WhcNMTUxMTI3MTQxMzI1WjBF\nMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\nZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\ngQC+luHIOf/z3ITksJAxkvnbSK2U5cGWBkSJP4zLSFDM7dWi5KSWNZvtWFEFhUAy\nAiyb7cjj3VMSWOnisqjFyMEeIHX/rD7CpnGVLIahTPftKJSvuJHrItU46SrdYoCw\nKKG0bhQU/R5rm4uD6i/5q6yFwZf1AW+HbL1SnpWt7zwd6QIDAQABo1AwTjAdBgNV\nHQ4EFgQU/9AFtc4VtYZjsZAUSZiLq62i8CgwHwYDVR0jBBgwFoAU/9AFtc4VtYZj\nsZAUSZiLq62i8CgwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCZIJmm\nr+uC5fdo2CcN+mC/dxCBIRPhL2ygckViO0L9U4J5y1YMO9isgWFvBiC++m4dynVg\nROtA6t2ORyAWRT79TSn05ATrBtcP9WBN21Yd+B997Gr9mMCNFrxzTPFJ18H/ZatA\nXbgMN9t8rzOtI1VH8t0siSNDiqmoNJDjrqT2sw==\n-----END CERTIFICATE-----",
            x5t: "Ps-NZCLZNIV7n3yXDeSw_iWXwBw",
            e: "010001",
            n: "be96e1c839fff3dc84e4b0903192f9db48ad94e5c1960644893f8ccb4850ccedd5a2e4a496359bed585105854032022c9bedc8e3dd531258e9e2b2a8c5c8c11e2075ffac3ec2a671952c86a14cf7ed2894afb891eb22d538e92add6280b028a1b46e1414fd1e6b9b8b83ea2ff9abac85c197f5016f876cbd529e95adef3c1de9"
          },
          {
            length: 2048,
            pem: "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAOxKOTiKDSERMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMTUxMDI4MTQxMzUxWhcNMTUxMTI3MTQxMzUxWjBF\nMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\nZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\nCgKCAQEAvtJcnQRc77P5qRn3mEDBVcI7s6iXAnh31KGg8OtlOwtOgNvlH6oAIK9i\nZsBhLpLZX4nQLLJWcqrDbyD2rN+idlabn8sXcES311YDZcysgd7roUdI+3pwBGZ/\nm1hsNNXt1OAq+Ih/LO+f3vjXnzoblcAF1a0YnATu3Q9V3XDP04vE3o85zsSJMtXF\nWMz7QmvD4xo6TJR9qDUZ3psfqvUjeozTY4+XZt4Hhy/m+Cuu1oKT9wdUSF5t/uF5\nWV05iRQo4D/46yxMtN+L1tJpqSfQa3LGLJGPnLKxufEFMij1YuwSha5XdufiOt0Y\nwjLe1FYbFD6id4hN0uod2ebtGB5AtQIDAQABo1AwTjAdBgNVHQ4EFgQUHEn1jX/W\nqc+pXOkb4UxGL6ZbL28wHwYDVR0jBBgwFoAUHEn1jX/Wqc+pXOkb4UxGL6ZbL28w\nDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAomA2XRa7dCUVJc6eeErh\n9Ti7t1EJGtABMmZcvep5erareRLHiKcHavtaj2u2f6QaQh3/GmclclKCCT88C/Xe\nR5SwUtZjKw3ymARBfvQCvfxVCpy3r6h4o3/b4DiqHrqX8XwUtFNzTkfrqlIzmntq\nvT9pE9NvFEtiZmsoH8q+Q3ntsIKHVb5Noi4q0+LyxcjDiVUbnG5IXa534v+B6mAN\nVygG68cdCDXbHgK+9U8gg8EgWf0++uoChXYWucAMsQK2qJ5vKHjGcSyPwQXlukWR\n7wXr7qEjtSpUzPe3Vrsr9OBsfhRT5oZA35Ev9wLWTeMcVWqe3Gx5w6aZafvZNzrz\npQ==\n-----END CERTIFICATE-----",
            x5t: "8kpt82VqMd_YS8irOCxJOg6kTDA",
            e: "010001",
            n: "bed25c9d045cefb3f9a919f79840c155c23bb3a897027877d4a1a0f0eb653b0b4e80dbe51faa0020af6266c0612e92d95f89d02cb25672aac36f20f6acdfa276569b9fcb177044b7d7560365ccac81deeba14748fb7a7004667f9b586c34d5edd4e02af8887f2cef9fdef8d79f3a1b95c005d5ad189c04eedd0f55dd70cfd38bc4de8f39cec48932d5c558ccfb426bc3e31a3a4c947da83519de9b1faaf5237a8cd3638f9766de07872fe6f82baed68293f70754485e6dfee179595d39891428e03ff8eb2c4cb4df8bd6d269a927d06b72c62c918f9cb2b1b9f1053228f562ec1285ae5776e7e23add18c232ded4561b143ea277884dd2ea1dd9e6ed181e40b5"
          },
          {
            length: 4096,
            pem: "-----BEGIN CERTIFICATE-----\nMIIFXTCCA0WgAwIBAgIJAIa1PteikpgXMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV\nBAYTAlVTMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX\naWRnaXRzIFB0eSBMdGQwHhcNMTUxMDI4MTQxMzU5WhcNMTUxMTI3MTQxMzU5WjBF\nMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50\nZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC\nCgKCAgEA9cCXgJhbwfA9O7DVEAjj6VpkSfmzQSo72x6pD7HMdD3ctR9A7Fbi/KsI\nhSbAlOxvDFUGvxdMcuGkulz4zg91ImD9ITOMrF4lUJcEMhrZq2XLzGALkwriX1+d\nCbCkd/hcfjtTzXQ92qG5iSsizuXNJSZaicBB05xANgI4YsosTeU2TgTXAI7K4t6c\nZ1mlCr/JBuJvi6sva1Oq/z+nofC3rb8DEQnkqrKrvTuzAibKgp5jBEEB1QW7jHD3\n5w8yx8yB5DokVdLCHvn6Ud2h+ZrrN7vuNeoy5uZu92iAugwzZwbT+E8a7KmiY5VL\n5jEfFTQumePDQjAlA5zO5dKyIn4/TyKfuJmIQBDxZXvx7mJQJpqNkTj4IotfXEPC\nfMq78fT4SOHFVkqw4JJf1HE0DLEk9ejnC/0GGDWLE8jRXlwj72hcHEXGVepjtusL\ntvgXzAvF6kbdqBAXvjlikfSZSZSieXZCM1CSAIrJ4tpLb67ZDGkKNqai55l66vzu\nPqTPenqtxNr81DrDG8s2BtHhoGstK+1SJXdiMrCSsc/awsUn7MoBoXD2Pq+eI2Rt\npWv+ZnPfnm+A6OhLpztYrEACY6/hv1hPAjg2O5RCaiS/fkJuMpRXB/mOw3VbTmG+\nS8Z6v3EnyDkc5zD5pNrI0e0QOjQq0z/RxrYKXw2EEhF7CNPhkasCAwEAAaNQME4w\nHQYDVR0OBBYEFCcq0Y/3BFmESZrebwaLL9r76nH0MB8GA1UdIwQYMBaAFCcq0Y/3\nBFmESZrebwaLL9r76nH0MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIB\nADZfWIxQYBPFjub8ZB5NNL/8Ro9oYmGdliCtw/MKqkuURzYBd02fNgdLc/SgcGJ7\nluap/REB8i2QvniD4yhprZMdP7nb6762Xmz2GmN0O5R058J+Sd4hrZQhFvRnZXEN\nHqH+bc8qMtFdHqLkwWWOpLJEpvUgZK+WiiFSh1ALnzrxFSxLd3us/ZS/m9nhcJhI\nO6mDMK/JfggkRAbmJGitPSVKCJl5STw6HsGou/Q1q2se1Yq/Rf5jVj92spzOQm4a\nc0rCQwmNEvjH7LAToy8VNnUJ/N32/nAt0AXVRdLiRBg/Wjjb2DWx/nlkhOe2tunN\no88PHCU4vh8pnDHk6pdSc1Oa9pRu4Uin5M5/D3HObpWd9+pEiyzZ/kZ6tx9fms/j\nJWRlbpGmVa6+AwVrwufenDV5ng2yXqpdcVv2yN0dGJOSZTflb+m1KPOi5oYpSkOR\nCScLL+orL47nWhzS76qZzJy4Zcq+VceOLZrcYx+m8gAqqSZr//2HOCEIWDUFm9C6\nyCFY3FB3sVcuagw7KZIHOnVcRLjpnFBhnLuMMmLifccW0hzdLrRwIKQ052A5dv9b\nkxjRcHxIOvm8M68IJt7PbrxoqxMO7MXR2YpZ4AihRbDBq5LIP1HHI21f/pkA341Z\nQA9cuNRolfYDiA3gE2F9c/7Et0S0cmLoGY7ln2NCQuHh\n-----END CERTIFICATE-----",
            x5t: "sgnaAcCu-ZEFEGEPUuvuc4KWr90",
            e: "010001",
            n: "f5c09780985bc1f03d3bb0d51008e3e95a6449f9b3412a3bdb1ea90fb1cc743ddcb51f40ec56e2fcab088526c094ec6f0c5506bf174c72e1a4ba5cf8ce0f752260fd21338cac5e25509704321ad9ab65cbcc600b930ae25f5f9d09b0a477f85c7e3b53cd743ddaa1b9892b22cee5cd25265a89c041d39c4036023862ca2c4de5364e04d7008ecae2de9c6759a50abfc906e26f8bab2f6b53aaff3fa7a1f0b7adbf031109e4aab2abbd3bb30226ca829e63044101d505bb8c70f7e70f32c7cc81e43a2455d2c21ef9fa51dda1f99aeb37bbee35ea32e6e66ef76880ba0c336706d3f84f1aeca9a263954be6311f15342e99e3c3423025039ccee5d2b2227e3f4f229fb899884010f1657bf1ee6250269a8d9138f8228b5f5c43c27ccabbf1f4f848e1c5564ab0e0925fd471340cb124f5e8e70bfd0618358b13c8d15e5c23ef685c1c45c655ea63b6eb0bb6f817cc0bc5ea46dda81017be396291f4994994a2797642335092008ac9e2da4b6faed90c690a36a6a2e7997aeafcee3ea4cf7a7aadc4dafcd43ac31bcb3606d1e1a06b2d2bed5225776232b092b1cfdac2c527ecca01a170f63eaf9e23646da56bfe6673df9e6f80e8e84ba73b58ac400263afe1bf584f0238363b94426a24bf7e426e32945707f98ec3755b4e61be4bc67abf7127c8391ce730f9a4dac8d1ed103a342ad33fd1c6b60a5f0d8412117b08d3e191ab"
          }
        ];

        testCerts.map(function(entry){
          it("coerces a 'RSA:" + entry.length + "' CERTIFICATE PEM String to JWK.Key instance and calculates a proper x5t", function(){
            var promise = Promise.resolve();
            promise = promise.then(function(){
              var keystore = JWK.store.KeyStore.createKeyStore();
              return keystore.add(entry.pem, "pem");
            });

            promise = promise.then(function(key){
              assert.equal(key.kty, "RSA");
              assert.equal(key.length, entry.length);
              ["e", "n", "x5t"].forEach(function(prop){
                assert.equal(key.has(prop), true, "key.has(\"" + prop + "\")");
                assert.isNotNull(key.get(prop));
                assert.equal(key.get(prop).toString("hex"), entry[prop], "key.get(\"" + prop + "\")");
              });
            });

            return promise;
          });
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
