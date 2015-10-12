/*!
 * jwk/rsa.js - RSA Key Representation
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var ecutil = require("../algorithms/ec-util.js"),
    forge = require("../deps/forge"),
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

// Inspired by digitalbaazar/node-forge/js/rsa.js
var validators = {
  privateKey: {
    // ECPrivateKey
    name: "ECPrivateKey",
    tagClass: forge.asn1.Class.UNIVERSAL,
    type: forge.asn1.Type.SEQUENCE,
    constructed: true,
    value: [
      {
        // EC version
        name: "ECPrivateKey.version",
        tagClass: forge.asn1.Class.UNIVERSAL,
        type: forge.asn1.Type.INTEGER,
        constructed: false
      },
      {
        // private value (d)
        name: "ECPrivateKey.private",
        tagClass: forge.asn1.Class.UNIVERSAL,
        type: forge.asn1.Type.OCTETSTRING,
        constructed: false,
        capture: "d"
      },
      {
        // publicKey
        name: "ECPrivateKey.publicKey",
        tagClass: forge.asn1.Class.CONTEXT_SPECIFIC,
        constructed: true,
        value: [
          {
            name: "ECPrivateKey.point",
            tagClass: forge.asn1.Class.UNIVERSAL,
            type: forge.asn1.Type.BITSTRING,
            constructed: false,
            capture: "point"
          }
        ]
      }
    ]
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
  },
  import: function(input) {
    if ("1.2.840.10045.2.1" !== input.keyOid) {
      return null;
    }

    // coerce key params to OID
    var crv;
    if (input.keyParams && forge.asn1.Type.OID === input.keyParams.type) {
      crv = forge.asn1.derToOid(input.keyParams.value);
      // convert OID to common name
      switch (crv) {
        case "1.2.840.10045.3.1.7":
          crv = "P-256";
          break;
        case "1.3.132.0.34":
          crv = "P-384";
          break;
        case "1.3.132.0.37":
          crv = "P-521";
          break;
        default:
          return null;
      }
    }

    var capture = {},
        errors = [];
    if ("private" === input.type) {
      // coerce capture.value to DER *iff* private
      if ("string" === typeof input.keyValue) {
        input.keyValue = forge.asn1.fromDer(input.keyValue);
      } else if (Array.isArray(input.keyValue)) {
        input.keyValue = input.keyValue[0];
      }

      if (!forge.asn1.validate(input.keyValue,
                               validators.privateKey,
                               capture,
                               errors)) {
        return null;
      }
    } else {
      capture.point = input.keyValue;
    }

    // convert factors to Buffers
    var output = {
      kty: "EC",
      crv: crv
    };
    if (capture.d) {
      output.d = new Buffer(capture.d, "binary");
    }
    if (capture.point) {
      var pt = new Buffer(capture.point, "binary");
      // only support uncompressed
      if (4 !== pt.readUInt16BE(0)) {
        return null;
      }
      pt = pt.slice(2);
      var len = pt.length / 2;
      output.x = pt.slice(0, len);
      output.y = pt.slice(len);
    }
    return output;
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
