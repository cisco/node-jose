/*!
 * jwk/rsa.js - RSA Key Representation
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var forge = require("../deps/forge.js");

var JWK = {
  BaseKey: require("./basekey.js"),
  helpers: require("./helpers.js")
};

var SIG_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512"
];
var WRAP_ALGS = [
  "RSA-OAEP",
  "RSA-OAEP-256",
  "RSA1_5"
];

var JWKRsaCfg = {
  publicKey: function(props) {
    var fields = JWK.helpers.COMMON_PROPS.concat([
      {name: "n", type: "binary"},
      {name: "e", type: "binary"}
    ]);
    var pk;
    pk = JWK.helpers.unpackProps(props, fields);
    if (pk && pk.n && pk.e) {
      pk.length = pk.n.length * 8;
    } else {
      delete pk.e;
      delete pk.n;
    }

    return pk;
  },
  privateKey: function(props) {
    var fields = JWK.helpers.COMMON_PROPS.concat([
      {name: "n", type: "binary"},
      {name: "e", type: "binary"},
      {name: "d", type: "binary"},
      {name: "p", type: "binary"},
      {name: "q", type: "binary"},
      {name: "dp", type: "binary"},
      {name: "dq", type: "binary"},
      {name: "qi", type: "binary"}
    ]);

    var pk;
    pk = JWK.helpers.unpackProps(props, fields);
    if (pk && pk.d && pk.n && pk.e && pk.p && pk.q && pk.dp && pk.dq && pk.qi) {
      pk.length = pk.d.length * 8;
    } else {
      pk = undefined;
    }

    return pk;
  },
  algorithms: function(keys, mode) {
    switch (mode) {
    case "encrypt":
    case "decrypt":
      return [];
    case "wrap":
      return (keys.public && WRAP_ALGS.slice()) || [];
    case "unwrap":
      return (keys.private && WRAP_ALGS.slice()) || [];
    case "sign":
      return (keys.private && SIG_ALGS.slice()) || [];
    case "verify":
      return (keys.public && SIG_ALGS.slice()) || [];
    }

    return [];
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

function convertBNtoBuffer(bn) {
  bn = bn.toString(16);
  if (bn.length % 2) {
    bn = "0" + bn;
  }
  return new Buffer(bn, "hex");
}

// Factory
var JWKRsaFactory = {
  kty: "RSA",
  prepare: function() {
    // TODO: validate key properties
    return Promise.resolve(JWKRsaCfg);
  },
  generate: function(size) {
    // TODO: validate key sizes
    var key = forge.pki.rsa.generateKeyPair({
      bits: size,
      e: 0x010001
    });
    key = key.privateKey;

    // convert to JSON-ish
    var result = {};
    [
      "e",
      "n",
      "d",
      "p",
      "q",
      {incoming: "dP", outgoing: "dp"},
      {incoming: "dQ", outgoing: "dq"},
      {incoming: "qInv", outgoing: "qi"}
    ].forEach(function(f) {
      var incoming,
          outgoing;

      if ("string" === typeof f) {
        incoming = outgoing = f;
      } else {
        incoming = f.incoming;
        outgoing = f.outgoing;
      }

      if (incoming in key) {
        result[outgoing] = convertBNtoBuffer(key[incoming]);
      }
    });

    return Promise.resolve(result);
  }
};

// public API
module.exports = Object.freeze({
  config: JWKRsaCfg,
  factory: JWKRsaFactory
});

// registration
(function(REGISTRY) {
  REGISTRY.register(JWKRsaFactory);
})(require("./keystore").registry);
