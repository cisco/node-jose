/*!
 * jwk/rsa.js - RSA Key Representation
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var ecutil = require("../algorithms/ec-util.js"),
    depsecc = require("../deps/ecc");

var JWK = {
  BaseKey: require("./basekey.js"),
  helpers: require("./helpers.js")
};

var SIG_ALGS = [
  "ES256",
  "ES384",
  "ES512"
];
var WRAP_ALGS = [
  "ECDH-ES",
  "ECDH-ES+A128KW",
  "ECDH-ES+A192KW",
  "ECDH-ES+A256KW"
];

var JWKEcCfg = {
  publicKey: function(props) {
    var fields = JWK.helpers.COMMON_PROPS.concat([
      {name: "crv", type: "string"},
      {name: "x", type: "binary"},
      {name: "y", type: "binary"}
    ]);
    var pk = JWK.helpers.unpackProps(props, fields);
    if (pk && pk.crv && pk.x && pk.y) {
      pk.length = ecutil.curveSize(pk.crv);
    } else {
      delete pk.crv;
      delete pk.x;
      delete pk.y;
    }

    return pk;
  },
  privateKey: function(props) {
    var fields = JWK.helpers.COMMON_PROPS.concat([
      {name: "crv", type: "string"},
      {name: "x", type: "binary"},
      {name: "y", type: "binary"},
      {name: "d", type: "binary"}
    ]);
    var pk = JWK.helpers.unpackProps(props, fields);
    if (pk && pk.crv && pk.x && pk.y && pk.d) {
      pk.length = ecutil.curveSize(pk.crv);
    } else {
      pk = undefined;
    }

    return pk;
  },
  algorithms: function(keys, mode) {
    var len = (keys.public && keys.public.length) ||
              (keys.private && keys.private.length) ||
              0;
    // NOTE: 521 is the actual, but 512 is the expected
    if (len === 521) {
        len = 512;
    }

    switch (mode) {
      case "encrypt":
      case "decrypt":
        return [];
      case "wrap":
        return (keys.public && WRAP_ALGS) || [];
      case "unwrap":
        return (keys.private && WRAP_ALGS) || [];
      case "sign":
        if (!keys.private) {
          return [];
        }
        return SIG_ALGS.filter(function(a) {
          return (a === ("ES" + len));
        });
      case "verify":
        if (!keys.public) {
          return [];
        }
        return SIG_ALGS.filter(function(a) {
          return (a === ("ES" + len));
        });
    }
  },

  encryptKey: function(alg, keys) {
    return keys.public;
  },
  decryptKey: function(alg, keys) {
    return keys.private;
  },

  wrapKey: function(alg, keys) {
    return keys.public;
  },
  unwrapKey: function(alg, keys) {
    return keys.private;
  },

  signKey: function(alg, keys) {
    return keys.private;
  },
  verifyKey: function(alg, keys) {
    return keys.public;
  }
};

var JWKEcFactory = {
  kty: "EC",
  prepare: function() {
    return Promise.resolve(JWKEcCfg);
  },
  generate: function(size) {
    var keypair = depsecc.generateKeyPair(size);
    var result = {
      "crv": size,
      "x": keypair.public.x,
      "y": keypair.public.y,
      "d": keypair.private.d
    };
    return Promise.resolve(result);
  }
};
// public API
module.exports = Object.freeze({
  config: JWKEcCfg,
  factory: JWKEcFactory
});

// registration
(function(REGISTRY) {
  REGISTRY.register(JWKEcFactory);
})(require("./keystore").registry);
