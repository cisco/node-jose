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

  describe("query", function() {

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
