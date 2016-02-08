/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var JWK = {
  BaseKey: require("../../lib/jwk/basekey.js"),
  helpers: require("../../lib/jwk/helpers.js"),
  CONSTANTS: require("../../lib/jwk/constants.js")
};
var util = require("../../lib/util");

describe("jwk/basekey", function() {
  var GENERIC_CFG = {
    publicKey: function(props) {
      var fields = JWK.helpers.COMMON_PROPS.concat([
        {name: "pub", type: "binary"}
      ]);

      var pk = JWK.helpers.unpackProps(props, fields);
      if (pk.pub) {
        pk.length = pk.pub.length * 8;
      }

      return pk;
    },
    privateKey: function(props) {
      var fields = JWK.helpers.COMMON_PROPS.concat([
        {name: "prv", type: "binary"}
      ]);

      var pk = JWK.helpers.unpackProps(props, fields);
      if (pk.prv) {
        pk.length = pk.prv.length * 8;
      }

      return pk;
    },
    thumbprint: function(json) {
      var fields = {};
      fields.pub = json.public.pub;
      fields.kty = "DUMMY";
      return fields;
    },
    algorithms: function(keys, mode) {
      var supported;
      switch (mode) {
        case JWK.CONSTANTS.MODE_SIGN:
          supported = keys.private &&
                      keys.private.prv &&
                      ["HS256", "HS384", "HS512"];
          break;
        case JWK.CONSTANTS.MODE_VERIFY:
          supported = keys.public &&
                      keys.public.pub &&
                      ["HS256", "HS384", "HS512"];
          break;
        case JWK.CONSTANTS.MODE_ENCRYPT:
          supported = keys.public &&
                      keys.public.pub &&
                      ["A128GCM", "A192GCM", "A256GCM"];
          break;
        case JWK.CONSTANTS.MODE_DECRYPT:
          supported = keys.private &&
                      keys.private.prv &&
                      ["A128GCM", "A192GCM", "A256GCM"];
          break;
        case JWK.CONSTANTS.MODE_WRAP:
          supported = keys.public &&
                      keys.public.pub &&
                      ["A128KW", "A192KW", "A256KW"];
          break;
        case JWK.CONSTANTS.MODE_UNWRAP:
          supported = keys.private &&
                      keys.private.prv &&
                      ["A128KW", "A192KW", "A256KW"];
          break;
      }

      return supported || [];
    }
  };
  function createInstance(props) {
    var store = {};
    return new JWK.BaseKey("DUMMY", store, props, GENERIC_CFG);
  }

  describe("ctor", function() {
    it("creates a generic BaseKey", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      inst = new JWK.BaseKey("DUMMY", keystore, props, GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.equal(inst.kid, props.kid);
      assert.equal(inst.use, "enc");
      assert.equal(inst.alg, "A128GCM");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.ok(inst.has("kid"));
      assert.equal(inst.get("kid"), "somevalue");
      assert.ok(inst.has("use"));
      assert.equal(inst.get("use"), "enc");
      assert.ok(inst.has("alg"));
      assert.equal(inst.get("alg"), "A128GCM");
      assert.ok(inst.has("pub"));
      assert.equal(util.base64url.encode(inst.get("pub")),
                   props.pub);
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });

      // private properties
      assert.ok(inst.has("prv", true));
      assert.equal(util.base64url.encode(inst.get("prv", true)),
                   props.prv);
      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });
    });
    it("creates a generic BaseKey with extras", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM",
        exp: "2015-01-29T11:15:01-07:00",
        iss: "nobody@nowhere"
      };
      inst = new JWK.BaseKey("DUMMY", keystore, props, GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.equal(inst.kid, props.kid);
      assert.equal(inst.use, "enc");
      assert.equal(inst.alg, "A128GCM");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.ok(inst.has("kid"));
      assert.equal(inst.get("kid"), "somevalue");
      assert.ok(inst.has("use"));
      assert.equal(inst.get("use"), "enc");
      assert.ok(inst.has("alg"));
      assert.equal(inst.get("alg"), "A128GCM");
      assert.ok(inst.has("pub"));
      assert.equal(util.base64url.encode(inst.get("pub")),
                   props.pub);
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.ok(inst.has("exp"));
      assert.equal(inst.get("exp"), "2015-01-29T11:15:01-07:00");
      assert.ok(inst.has("iss"));
      assert.equal(inst.get("iss"), "nobody@nowhere");
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc",
        "exp": "2015-01-29T11:15:01-07:00",
        "iss": "nobody@nowhere"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc",
        "exp": "2015-01-29T11:15:01-07:00",
        "iss": "nobody@nowhere"
      });

      // private properties
      assert.ok(inst.has("prv", true));
      assert.equal(util.base64url.encode(inst.get("prv", true)),
                   props.prv);
      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc",
        "exp": "2015-01-29T11:15:01-07:00",
        "iss": "nobody@nowhere"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc",
        "exp": "2015-01-29T11:15:01-07:00",
        "iss": "nobody@nowhere"
      });
    });
    it("creates a generic BaseKey with a props string", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      inst = new JWK.BaseKey("DUMMY",
                             keystore,
                             JSON.stringify(props),
                             GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.equal(inst.kid, props.kid);
      assert.equal(inst.use, "enc");
      assert.equal(inst.alg, "A128GCM");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.ok(inst.has("kid"));
      assert.equal(inst.get("kid"), "somevalue");
      assert.ok(inst.has("use"));
      assert.equal(inst.get("use"), "enc");
      assert.ok(inst.has("alg"));
      assert.equal(inst.get("alg"), "A128GCM");
      assert.ok(inst.has("pub"));
      assert.equal(util.base64url.encode(inst.get("pub")),
                   props.pub);
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });

      // private properties
      assert.ok(inst.has("prv", true));
      assert.equal(util.base64url.encode(inst.get("prv", true)),
                   props.prv);
      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });
    });
    it("creates a generic BaseKey without a private key", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        use: "enc",
        alg: "A128GCM"
      };
      inst = new JWK.BaseKey("DUMMY", keystore, props, GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.equal(inst.kid, props.kid);
      assert.equal(inst.use, "enc");
      assert.equal(inst.alg, "A128GCM");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.ok(inst.has("kid"));
      assert.equal(inst.get("kid"), "somevalue");
      assert.ok(inst.has("use"));
      assert.equal(inst.get("use"), "enc");
      assert.ok(inst.has("alg"));
      assert.equal(inst.get("alg"), "A128GCM");
      assert.ok(inst.has("pub"));
      assert.equal(util.base64url.encode(inst.get("pub")),
                   props.pub);
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });

      // private properties
      assert.notOk(inst.has("prv", true));
      assert.isNull(inst.get("prv", true));
      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM",
        "use": "enc"
      });
    });
    it("creates a generic BaseKey without a public key", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        kid: "somevalue",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      inst = new JWK.BaseKey("DUMMY", keystore, props, GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.equal(inst.kid, props.kid);
      assert.equal(inst.use, "enc");
      assert.equal(inst.alg, "A128GCM");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.ok(inst.has("kid"));
      assert.equal(inst.get("kid"), "somevalue");
      assert.ok(inst.has("use"));
      assert.equal(inst.get("use"), "enc");
      assert.ok(inst.has("alg"));
      assert.equal(inst.get("alg"), "A128GCM");
      assert.notOk(inst.has("pub"));
      assert.isNull(inst.get("pub"));
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "alg": "A128GCM",
        "use": "enc"
      });

      // private properties
      assert.ok(inst.has("prv", true));
      assert.equal(util.base64url.encode(inst.get("prv", true)),
                   props.prv);
      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "alg": "A128GCM",
        "use": "enc"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "alg": "A128GCM",
        "use": "enc"
      });
    });
    it("creates a generic BaseKey with implied values", function() {
      var keystore = new Date(),
          props,
          inst;

      props = {
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      };
      inst = new JWK.BaseKey("DUMMY", keystore, props, GENERIC_CFG);
      // built-in properties
      assert.strictEqual(inst.keystore, keystore);
      assert.equal(inst.length, 128);
      assert.equal(inst.kty, "DUMMY");
      assert.isString(inst.kid);
      assert.equal(inst.use, "");
      assert.equal(inst.alg, "");

      // public-only properties
      assert.ok(inst.has("kty"));
      assert.equal(inst.get("kty"), "DUMMY");
      assert.notOk(inst.has("use"));
      assert.isNull(inst.get("use"));
      assert.notOk(inst.has("alg"));
      assert.isNull(inst.get("alg"));
      assert.ok(inst.has("pub"));
      assert.equal(util.base64url.encode(inst.get("pub")),
                   props.pub);
      assert.notOk(inst.has("prv"));
      assert.isNull(inst.get("prv"));
      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": inst.kid,
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ")
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": inst.kid,
        "pub": "Lc3EY3_96tfej0F7Afa0TQ"
      });

      // private properties
      assert.ok(inst.has("prv", true));
      assert.equal(util.base64url.encode(inst.get("prv", true)),
                   props.prv);
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": inst.kid,
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ"
      });
    });

    it("fails to create with missing arguments", function() {
      var keystore = new Date(),
          props = {
            kid: "somevalue",
            pub: "Lc3EY3_96tfej0F7Afa0TQ",
            prv: "SBh6LBt1DBTeyHTvwDgSjg",
            use: "enc",
            alg: "A128GCM"
          };

      /* eslint no-unused-vars: [0] */
      assert.throw(function() {
        var key = new JWK.BaseKey(null, keystore, props, GENERIC_CFG);
      }, "kty cannot be null");
      assert.throw(function() {
        var key = new JWK.BaseKey("DUMMY", null, props, GENERIC_CFG);
      }, "keystore cannot be null");
      assert.throw(function() {
        var key = new JWK.BaseKey("DUMMY", keystore, null, GENERIC_CFG);
      }, "props cannot be null");
      assert.throw(function() {
        var key = new JWK.BaseKey("DUMMY", keystore, props, null);
      });
    });
  });

  describe("serialization", function() {
    it("serializes no options", function() {
      var props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      var inst = createInstance(props);

      assert.deepEqual(inst.toObject(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "use": "enc",
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON(), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "use": "enc",
        "alg": "A128GCM"
      });

      assert.deepEqual(inst.toObject(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "use": "enc",
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON(true), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "use": "enc",
        "alg": "A128GCM"
      });
    });
    it("serializes with excluded", function() {
      var props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      var inst = createInstance(props);

      assert.deepEqual(inst.toObject(false, ["kid", "use"]), {
        "kty": "DUMMY",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON(false, ["kid", "use"]), {
        "kty": "DUMMY",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM"
      });

      assert.deepEqual(inst.toObject(true, ["kid", "use"]), {
        "kty": "DUMMY",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "prv": util.base64url.decode("SBh6LBt1DBTeyHTvwDgSjg"),
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON(true, ["kid", "use"]), {
        "kty": "DUMMY",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "prv": "SBh6LBt1DBTeyHTvwDgSjg",
        "alg": "A128GCM"
      });
    });
    it("serializes with excluded first", function() {
      var props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      var inst = createInstance(props);

      assert.deepEqual(inst.toObject(["kid", "use"]), {
        "kty": "DUMMY",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON(["kid", "use"]), {
        "kty": "DUMMY",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "alg": "A128GCM"
      });
    });
    it("ignores isPrivate if not a Boolean", function() {
      var props = {
        kid: "somevalue",
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc",
        alg: "A128GCM"
      };
      var inst = createInstance(props);

      assert.deepEqual(inst.toObject("42"), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": util.base64url.decode("Lc3EY3_96tfej0F7Afa0TQ"),
        "use": "enc",
        "alg": "A128GCM"
      });
      assert.deepEqual(inst.toJSON("42"), {
        "kty": "DUMMY",
        "kid": "somevalue",
        "pub": "Lc3EY3_96tfej0F7Afa0TQ",
        "use": "enc",
        "alg": "A128GCM"
      });
    });
  });

  describe("thumbprints", function() {
    it("returns a promise for a 'default' thumbprint", function() {
      var inst;

      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      var p = inst.thumbprint();
      p = p.then(function(print) {
        assert.equal(print.toString("hex"),
                     "37e91104e7e5b0b923926844c710a100aa48fa14554e85fc901a5ebc99cd13e6");
      });
      return p;
    });
    it("returns a promise for a specified thumbprint", function() {
      var inst;

      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      var p = inst.thumbprint("SHA-1");
      p = p.then(function(print) {
        assert.equal(print.toString("hex"),
                     "d14514ab53c383798343e3577ad12947e84fad40");
      });
      return p;
    });
    it("fails on invalid hash algoritm", function() {
      var inst;

      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      var p = inst.thumbprint("SHA3");
      p = p.then(function(print) {
        assert.ok(false, "unexpected success");
      }, function(err) {
        assert.ok(err);
      });
      return p;
    });
    it("returns the same thumbprint as before", function() {
      var inst;

      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      var p = inst.thumbprint();
      p = p.then(function(print) {
        assert.equal(print.toString("hex"),
                     "37e91104e7e5b0b923926844c710a100aa48fa14554e85fc901a5ebc99cd13e6");
        return inst.thumbprint();
      });
      p = p.then(function(print) {
        assert.equal(print.toString("hex"),
                     "37e91104e7e5b0b923926844c710a100aa48fa14554e85fc901a5ebc99cd13e6");
      });
      return p;
    });
  });
  describe("algorithms and supports", function() {
    it("returns all supported algorithms", function() {
      var inst;

      // all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512",
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));
    });
    it("returns a specific mode of supported algorithms", function() {
      var inst;

      // all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.ok(inst.supports("HS256", JWK.CONSTANTS.MODE_SIGN));
      assert.ok(inst.supports("HS384", JWK.CONSTANTS.MODE_SIGN));
      assert.ok(inst.supports("HS512", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_SIGN));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.ok(inst.supports("HS256", JWK.CONSTANTS.MODE_VERIFY));
      assert.ok(inst.supports("HS384", JWK.CONSTANTS.MODE_VERIFY));
      assert.ok(inst.supports("HS512", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_VERIFY));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A128GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A192GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A256GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_ENCRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A128GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A192GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A256GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_DECRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A128KW", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A192KW", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A256KW", JWK.CONSTANTS.MODE_WRAP));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A128KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A192KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A256KW", JWK.CONSTANTS.MODE_UNWRAP));

      // public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ"
      });
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_SIGN));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.ok(inst.supports("HS256", JWK.CONSTANTS.MODE_VERIFY));
      assert.ok(inst.supports("HS384", JWK.CONSTANTS.MODE_VERIFY));
      assert.ok(inst.supports("HS512", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_VERIFY));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A128GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A192GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.ok(inst.supports("A256GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_ENCRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_DECRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A128KW", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A192KW", JWK.CONSTANTS.MODE_WRAP));
      assert.ok(inst.supports("A256KW", JWK.CONSTANTS.MODE_WRAP));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_UNWRAP));

      // private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg"
      });
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.ok(inst.supports("HS256", JWK.CONSTANTS.MODE_SIGN));
      assert.ok(inst.supports("HS384", JWK.CONSTANTS.MODE_SIGN));
      assert.ok(inst.supports("HS512", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_SIGN));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_SIGN));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_VERIFY));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_VERIFY));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_ENCRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_ENCRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A128GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A192GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.ok(inst.supports("A256GCM", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_DECRYPT));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_DECRYPT));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A128KW", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A192KW", JWK.CONSTANTS.MODE_WRAP));
      assert.notOk(inst.supports("A256KW", JWK.CONSTANTS.MODE_WRAP));

      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS384", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("HS512", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A128GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A192GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.notOk(inst.supports("A256GCM", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A128KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A192KW", JWK.CONSTANTS.MODE_UNWRAP));
      assert.ok(inst.supports("A256KW", JWK.CONSTANTS.MODE_UNWRAP));
    });
    it("returns supported algorithms based on 'use'", function() {
      var inst;

      // 'enc' all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // 'enc' public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        use: "enc"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // 'enc' private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "enc"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM",
        "A192GCM",
        "A256GCM",
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM",
        "A192GCM",
        "A256GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A128KW",
        "A192KW",
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.ok(inst.supports("A192GCM"));
      assert.ok(inst.supports("A256GCM"));
      assert.ok(inst.supports("A128KW"));
      assert.ok(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // 'sig' all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "sig"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'enc' public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        use: "sig"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'enc' private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        use: "sig"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS256",
        "HS384",
        "HS512"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.ok(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.ok(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));
    });
    it("returns supported algorithms based on 'alg'", function() {
      var inst;

      // 'HS384' all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "HS384"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'HS384' public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        alg: "HS384"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'HS384' private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "HS384"
      });
      assert.deepEqual(inst.algorithms(), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), [
        "HS384"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.ok(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'A128GCM' all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "A128GCM"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'A128GCM' public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        alg: "A128GCM"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'A128GCM' private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "A128GCM"
      });
      assert.deepEqual(inst.algorithms(), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), [
        "A128GCM"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.ok(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.notOk(inst.supports("A256KW"));

      // 'A256KW' all-all ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "A256KW"
      });
      assert.deepEqual(inst.algorithms(), [
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // 'A256KW' public-only ops
      inst = createInstance({
        pub: "Lc3EY3_96tfej0F7Afa0TQ",
        alg: "A256KW"
      });
      assert.deepEqual(inst.algorithms(), [
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), [
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), []);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));

      // 'A256KW' private-only ops
      inst = createInstance({
        prv: "SBh6LBt1DBTeyHTvwDgSjg",
        alg: "A256KW"
      });
      assert.deepEqual(inst.algorithms(), [
        "A256KW"
      ]);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_SIGN), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_VERIFY), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_ENCRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_DECRYPT), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_WRAP), []);
      assert.deepEqual(inst.algorithms(JWK.CONSTANTS.MODE_UNWRAP), [
        "A256KW"
      ]);
      assert.notOk(inst.supports("HS256"));
      assert.notOk(inst.supports("HS384"));
      assert.notOk(inst.supports("HS512"));
      assert.notOk(inst.supports("A128GCM"));
      assert.notOk(inst.supports("A192GCM"));
      assert.notOk(inst.supports("A256GCM"));
      assert.notOk(inst.supports("A128KW"));
      assert.notOk(inst.supports("A192KW"));
      assert.ok(inst.supports("A256KW"));
    });
  });
});
