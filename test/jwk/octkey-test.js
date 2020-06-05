/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai"),
    forge = require("node-forge"),
    clone = require("lodash/clone"),
    merge = require("../../lib/util/merge");
var assert = chai.assert;

var JWK = {
  OCTET: require("../../lib/jwk/octkey.js"),
  BaseKey: require("../../lib/jwk/basekey.js"),
  store: require("../../lib/jwk/keystore.js"),
  helpers: require("../../lib/jwk/helpers.js"),
  CONSTANTS: require("../../lib/jwk/constants.js")
};
var util = require("../../lib/util");

describe("jwk/oct", function() {
  describe("#publicKey", function() {
    it("prepares a publicKey", function() {
      var props,
          actual,
          expected;

      props = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": "Obdi7uR-5mc3Zbo0HtI-CQ",
        "exp": "2025-01-26T00:00:00Z"
      };
      actual = JWK.OCTET.config.publicKey(props);
      expected = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
      };
      assert.deepEqual(actual, expected);
    });
    it("prepares a publicKey with missing key value", function() {
      var props,
          actual,
          expected;

      props = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "exp": "2025-01-26T00:00:00Z"
      };
      actual = JWK.OCTET.config.publicKey(props);
      expected = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
      };
      assert.deepEqual(actual, expected);
    });
  });
  describe("#privateKey", function() {
    it("prepares a privateKey", function() {
      var props,
          actual,
          expected;

      props = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": "Obdi7uR-5mc3Zbo0HtI-CQ",
        "exp": "2025-01-26T00:00:00Z"
      };
      actual = JWK.OCTET.config.privateKey(props);
      expected = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": util.base64url.decode("Obdi7uR-5mc3Zbo0HtI-CQ"),
        "length": 128
      };
      assert.deepEqual(actual, expected);
    });
    it("returns undefined for missing key value", function() {
      var props,
          actual;

      props = {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "exp": "2025-01-26T00:00:00Z"
      };
      actual = JWK.OCTET.config.privateKey(props);
      assert.isUndefined(actual);
    });
  });

  describe("#thumbprint", function() {
    var json = {
      private: {
        "k": "Obdi7uR-5mc3Zbo0HtI-CQ"
      }
    };
    it("returns required fields (minus kty)", function() {
      var expected = {
        k: "Obdi7uR-5mc3Zbo0HtI-CQ",
        kty: "oct"
      };
      var actual = JWK.OCTET.config.thumbprint(json);
      assert.deepEqual(actual, expected);
    });
  });

  describe("#encryptKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": util.base64url.decode("Obdi7uR-5mc3Zbo0HtI-CQ"),
        "length": 128
        }
      };

      var result = JWK.OCTET.config.encryptKey("A128GCM", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        }
      };

      var result = JWK.OCTET.config.encryptKey("A128GCM", keys);
      assert.isUndefined(result);
    });
    it("returns undefined for missing keys.private", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        }
      };

      var result = JWK.OCTET.config.encryptKey("A128GCM", keys);
      assert.isUndefined(result);
    });
  });
  describe("#encryptProps", function() {
    it("prepares string properties", function() {
      var props,
          adjusted;

      props = {
        iv: "f0uE_M5yFBbwGhHy",
        stuff: "hello"
      };
      adjusted = JWK.OCTET.config.encryptProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.equal(adjusted.stuff, "hello");
    });

    it("prepares Buffer properties", function() {
      var props,
          adjusted;

      props = {
        iv: util.base64url.decode("f0uE_M5yFBbwGhHy"),
        stuff: "hello"
      };
      adjusted = JWK.OCTET.config.encryptProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.equal(adjusted.stuff, "hello");
    });
  });

  describe("#decryptKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": util.base64url.decode("Obdi7uR-5mc3Zbo0HtI-CQ"),
        "length": 128
        }
      };

      var result = JWK.OCTET.config.decryptKey("A128GCM", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        }
      };

      var result = JWK.OCTET.config.decryptKey("A128GCM", keys);
      assert.isUndefined(result);
    });
  });
  describe("#decryptProps", function() {
    it("prepares string properties", function() {
      var props,
          adjusted;

      props = {
        iv: "f0uE_M5yFBbwGhHy",
        mac: "ZnNSux6e4oz6r85VHTE8jw"
      };
      adjusted = JWK.OCTET.config.decryptProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.ok(Buffer.isBuffer(adjusted.mac));
      assert.equal(util.base64url.encode(adjusted.mac), "ZnNSux6e4oz6r85VHTE8jw");
    });
    it("prepares Buffer properties", function() {
      var props,
          adjusted;

      props = {
        iv: util.base64url.decode("f0uE_M5yFBbwGhHy"),
        mac: util.base64url.decode("ZnNSux6e4oz6r85VHTE8jw")
      };
      adjusted = JWK.OCTET.config.decryptProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.ok(Buffer.isBuffer(adjusted.mac));
      assert.equal(util.base64url.encode(adjusted.mac), "ZnNSux6e4oz6r85VHTE8jw");
    });
  });

  describe("#wrapKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": util.base64url.decode("Obdi7uR-5mc3Zbo0HtI-CQ"),
        "length": 128
        }
      };

      var result = JWK.OCTET.config.wrapKey("A128GCM", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        }
      };

      var result = JWK.OCTET.config.wrapKey("A128GCM", keys);
      assert.isUndefined(result);
    });
  });
  describe("#wrapProps", function() {
    it("prepares string properties", function() {
      var props,
          adjusted;

      props = {
        iv: "f0uE_M5yFBbwGhHy",
        stuff: "hello"
      };
      adjusted = JWK.OCTET.config.wrapProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.equal(adjusted.stuff, "hello");
    });

    it("prepares Buffer properties", function() {
      var props,
          adjusted;

      props = {
        iv: util.base64url.decode("f0uE_M5yFBbwGhHy"),
        stuff: "hello"
      };
      adjusted = JWK.OCTET.config.wrapProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.equal(adjusted.stuff, "hello");
    });
  });

  describe("#unwrapKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM",
        "k": util.base64url.decode("Obdi7uR-5mc3Zbo0HtI-CQ"),
        "length": 128
        }
      };

      var result = JWK.OCTET.config.unwrapKey("A128GCM", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "A128GCM"
        }
      };

      var result = JWK.OCTET.config.unwrapKey("A128GCM", keys);
      assert.isUndefined(result);
    });
  });
  describe("#unwrapProps", function() {
    it("prepares string properties", function() {
      var props,
          adjusted;

      props = {
        iv: "f0uE_M5yFBbwGhHy",
        tag: "ZnNSux6e4oz6r85VHTE8jw"
      };
      adjusted = JWK.OCTET.config.unwrapProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.ok(Buffer.isBuffer(adjusted.tag));
      assert.equal(util.base64url.encode(adjusted.tag), "ZnNSux6e4oz6r85VHTE8jw");
    });
    it("prepares Buffer properties", function() {
      var props,
          adjusted;

      props = {
        iv: util.base64url.decode("f0uE_M5yFBbwGhHy"),
        tag: util.base64url.decode("ZnNSux6e4oz6r85VHTE8jw")
      };
      adjusted = JWK.OCTET.config.unwrapProps("A128GCM", props);
      assert.ok(Buffer.isBuffer(adjusted.iv));
      assert.equal(util.base64url.encode(adjusted.iv), "f0uE_M5yFBbwGhHy");
      assert.ok(Buffer.isBuffer(adjusted.tag));
      assert.equal(util.base64url.encode(adjusted.tag), "ZnNSux6e4oz6r85VHTE8jw");
    });
  });

  describe("#signKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "sig",
        "alg": "HS256"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256",
        "k": util.base64url.decode("FSvoH87JhcZHRloyWOgODO_Y-XkK4w0eyFMxO4JE-Yo"),
        "length": 256
        }
      };

      var result = JWK.OCTET.config.signKey("HS256", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256"
        }
      };

      var result = JWK.OCTET.config.signKey("HS256", keys);
      assert.isUndefined(result);
    });
  });


  describe("#verifyKey", function() {
    it("returns key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "sig",
        "alg": "HS256"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256",
        "k": util.base64url.decode("FSvoH87JhcZHRloyWOgODO_Y-XkK4w0eyFMxO4JE-Yo"),
        "length": 256
        }
      };

      var result = JWK.OCTET.config.verifyKey("HS256", keys);
      assert.equal(result, keys.private.k);
    });
    it("returns undefined for missing key value", function() {
      var keys = {
        public: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256"
        },
        private: {
        "kid": "somekey",
        "use": "enc",
        "alg": "HS256"
        }
      };

      var result = JWK.OCTET.config.verifyKey("HS256", keys);
      assert.isUndefined(result);
    });
  });

  describe("#algorithms", function() {
    function generateKeys(size, props) {
      props = merge({}, props || {}, {
        "k": Buffer.from(forge.random.getBytes(size / 8), "binary")
      });
      var keys = {};
      keys.public = JWK.OCTET.config.publicKey(clone(props));
      keys.private = JWK.OCTET.config.privateKey(clone(props));

      return keys;
    }
    it("returns the suite for 128-bit", function() {
      var keys = generateKeys(128);
      var algs;

      algs = JWK.OCTET.config.algorithms(keys, "sign");
      assert.deepEqual(algs, []);
      algs = JWK.OCTET.config.algorithms(keys, "verify");
      assert.deepEqual(algs, []);

      algs = JWK.OCTET.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, ["A128GCM"]);
      algs = JWK.OCTET.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, ["A128GCM"]);

      algs = JWK.OCTET.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["A128KW", "A128GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
      algs = JWK.OCTET.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["A128KW", "A128GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
    });
    it("returns the suite for 192-bit", function() {
      var keys = generateKeys(192);
      var algs;

      algs = JWK.OCTET.config.algorithms(keys, "sign");
      assert.deepEqual(algs, []);
      algs = JWK.OCTET.config.algorithms(keys, "verify");
      assert.deepEqual(algs, []);

      algs = JWK.OCTET.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, ["A192GCM"]);
      algs = JWK.OCTET.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, ["A192GCM"]);

      algs = JWK.OCTET.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["A192KW", "A192GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
      algs = JWK.OCTET.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["A192KW", "A192GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
    });
    it("returns the suite for 256-bit", function() {
      var keys = generateKeys(256);
      var algs;

      algs = JWK.OCTET.config.algorithms(keys, "sign");
      assert.deepEqual(algs, ["HS256"]);
      algs = JWK.OCTET.config.algorithms(keys, "verify");
      assert.deepEqual(algs, ["HS256"]);

      algs = JWK.OCTET.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, ["A256GCM", "A128CBC-HS256", "A128CBC+HS256"]);
      algs = JWK.OCTET.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, ["A256GCM", "A128CBC-HS256", "A128CBC+HS256"]);

      algs = JWK.OCTET.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["A256KW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
      algs = JWK.OCTET.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["A256KW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
    });
    it("returns the suite for 384-bit", function() {
      var keys = generateKeys(384);
      var algs;

      algs = JWK.OCTET.config.algorithms(keys, "sign");
      assert.deepEqual(algs, ["HS256", "HS384"]);
      algs = JWK.OCTET.config.algorithms(keys, "verify");
      assert.deepEqual(algs, ["HS256", "HS384"]);

      algs = JWK.OCTET.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, ["A192CBC-HS384", "A192CBC+HS384"]);
      algs = JWK.OCTET.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, ["A192CBC-HS384", "A192CBC+HS384"]);

      algs = JWK.OCTET.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
      algs = JWK.OCTET.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
    });
    it("returns the suite for 512-bit", function() {
      var keys = generateKeys(512);
      var algs;

      algs = JWK.OCTET.config.algorithms(keys, "sign");
      assert.deepEqual(algs, ["HS256", "HS384", "HS512"]);
      algs = JWK.OCTET.config.algorithms(keys, "verify");
      assert.deepEqual(algs, ["HS256", "HS384", "HS512"]);

      algs = JWK.OCTET.config.algorithms(keys, "encrypt");
      assert.deepEqual(algs, ["A256CBC-HS512", "A256CBC+HS512"]);
      algs = JWK.OCTET.config.algorithms(keys, "decrypt");
      assert.deepEqual(algs, ["A256CBC-HS512", "A256CBC+HS512"]);

      algs = JWK.OCTET.config.algorithms(keys, "wrap");
      assert.deepEqual(algs, ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
      algs = JWK.OCTET.config.algorithms(keys, "unwrap");
      assert.deepEqual(algs, ["PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW", "dir"]);
    });
  });

  describe("keystore integration", function() {
    it("generates a 'oct' JWK", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var promise = keystore.generate("oct", 128);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "oct");
        assert.equal(key.length, 128);
        assert.ok(!!key.get("k", true));

        assert.deepEqual(keystore.all(), [key]);
      });

      return promise;
    });
    it("generates a 'oct' JWK with props", function() {
      var keystore = JWK.store.KeyStore.createKeyStore();

      var props = {
        kid: "someid",
        use: "enc",
        alg: "A128GCM"
      };
      var promise = keystore.generate("oct", 128, props);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "oct");
        assert.equal(key.length, 128);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("use"), "enc");
        assert.equal(key.get("alg"), "A128GCM");
        assert.ok(!!key.get("k", true));

        assert.deepEqual(keystore.all(), [key]);
      });

      return promise;
    });

    function setupEncKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = {
        kty: "oct",
        kid: "someid",
        use: "enc",
        alg: "A128GCM",
        k: util.base64url.encode("816e39070410cf2184904da03ea5075a", "hex")
      };

      return keystore.add(jwk);
    }
    function setupSigKey() {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = {
        kty: "oct",
        kid: "someid",
        use: "sig",
        alg: "HS256",
        k: util.base64url.encode("9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176", "hex")
      };

      return keystore.add(jwk);
    }
    function setupWrapKey(keyval, alg) {
      var keystore = JWK.store.KeyStore.createKeyStore();
      var jwk = {
        kty: "oct",
        kid: "someid",
        use: "enc",
        alg: alg || "A128GCM",
        k: util.base64url.encode(keyval || "e98b72a9881a84ca6b76e0f43e68647a", "hex")
      };
      return keystore.add(jwk);
    }

    it("imports a 'oct' encryption JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupEncKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "oct");
        assert.equal(key.length, 128);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("k", true).toString("hex"), "816e39070410cf2184904da03ea5075a");
        assert.deepEqual(key.toJSON(true), {
          kty: "oct",
          kid: "someid",
          k: util.base64url.encode("816e39070410cf2184904da03ea5075a", "hex"),
          use: "enc",
          alg: "A128GCM"
        });
      });

      return promise;
    });

    it("imports a 'oct' signing JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupSigKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "oct");
        assert.equal(key.length, 320);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("k", true).toString("hex"), "9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176");
        assert.deepEqual(key.toJSON(true), {
          kty: "oct",
          kid: "someid",
          k: util.base64url.encode("9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176", "hex"),
          use: "sig",
          alg: "HS256"
        });
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "fdce868cfc9f1d400ac42190a55f2ee6f12ca04363c3b207f3c4c3c01e343e48");
      });

      return promise;
    });

    it("imports a 'oct' wrapping JWK", function() {
      var promise = Promise.resolve();

      promise = promise.then(setupWrapKey);
      promise = promise.then(function(key) {
        assert.equal(key.kty, "oct");
        assert.equal(key.length, 128);
        assert.equal(key.kid, "someid");
        assert.equal(key.get("k", true).toString("hex"), "e98b72a9881a84ca6b76e0f43e68647a");
        assert.deepEqual(key.toJSON(true), {
          kty: "oct",
          kid: "someid",
          k: util.base64url.encode("e98b72a9881a84ca6b76e0f43e68647a", "hex"),
          use: "enc",
          alg: "A128GCM"
        });
        return key.thumbprint();
      });
      promise = promise.then(function(print) {
        assert.equal(print.toString("hex"), "9006be7d413efbcdeb16d180fa7f84de2cbc7a0463f1a2d50c09a221b5b34cd9");
      });

      return promise;
    });

    it("encrypts via JWK", function() {
      var promise = setupEncKey();
      promise = promise.then(function(jwk) {
        var props = {
          iv: Buffer.from("32c367a3362613b27fc3e67e", "hex"),
          aad: Buffer.from("f2a30728ed874ee02983c294435d3c16", "hex")
        };

        var pdata = Buffer.from("ecafe96c67a1646744f1c891f5e69427", "hex");
        return jwk.encrypt("A128GCM", pdata, props);
      });
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), "552ebe012e7bcf90fcef712f8344e8f1");
        assert.equal(result.tag.toString("hex"), "ecaae9fc68276a45ab0ca3cb9dd9539f");
      });

      return promise;
    });
    it("decrypts via JWK", function() {
      var promise = setupEncKey();
      promise = promise.then(function(jwk) {
        var props = {
          iv: Buffer.from("32c367a3362613b27fc3e67e", "hex"),
          aad: Buffer.from("f2a30728ed874ee02983c294435d3c16", "hex"),
          tag: Buffer.from("ecaae9fc68276a45ab0ca3cb9dd9539f", "hex")
        };

        var cdata = Buffer.from("552ebe012e7bcf90fcef712f8344e8f1", "hex");
        return jwk.decrypt("A128GCM", cdata, props);
      });
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), "ecafe96c67a1646744f1c891f5e69427");
      });

      return promise;
    });
    it("signs via JWK", function() {
      var promise = setupSigKey();
      promise = promise.then(function(jwk) {
        var pdata = Buffer.from("b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e", "hex");
        return jwk.sign("HS256", pdata);
      });
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), "b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e");
        assert.equal(result.mac.toString("hex"), "769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b");
      });

      return promise;
    });
    it("verifies via JWK", function() {
      var promise = setupSigKey();
      promise = promise.then(function(jwk) {
        var pdata = Buffer.from("b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e", "hex");
        var mac = Buffer.from("769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b", "hex");
        return jwk.verify("HS256", pdata, mac);
      });
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), "b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e");
        assert.equal(result.mac.toString("hex"), "769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b");
        assert.equal(result.valid, true);
      });

      return promise;
    });
    it("wraps via JWK", function() {
      var promise = setupWrapKey("000102030405060708090a0b0c0d0e0f", "A128KW");
      promise = promise.then(function(jwk) {
        var props = {
          iv: Buffer.from("8b23299fde174053f3d652ba", "hex")
        };

        var pdata = Buffer.from("00112233445566778899aabbccddeeff", "hex");
        return jwk.wrap("A128KW", pdata, props);
      });
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5");
      });

      return promise;
    });
  });
});
