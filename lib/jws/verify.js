/*!
 * jws/verify.js - Verifies from a JWS
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var clone = require("lodash.clone"),
    merge = require("../util/merge"),
    base64url = require("../util/base64url"),
    JWK = require("../jwk");

/**
 * @class JWS.Verifier
 * @classdesc Parser of signed content.
 *
 * @description
 * **NOTE:** this class cannot be instantiated directly. Instead call {@link
 * JWS.createVerify}.
 */
var JWSVerifier = function(ks) {
  var assumedKey,
      keystore;

  if (JWK.isKey(ks)) {
      assumedKey = ks;
      keystore = assumedKey.keystore;
  } else if (JWK.isKeyStore(ks)) {
      keystore = ks;
  } else {
      throw new TypeError("Keystore must be provided");
  }

  Object.defineProperty(this, "verify", {
    value: function(input) {
      if ("string" === typeof input) {
        input = input.split(".");
        input = {
          payload: input[1],
          signatures: [
            {
              protected: input[0],
              signature: input[2]
            }
          ]
        };
      } else if (!input || "object" === input) {
        throw new Error("invalid input");
      }

      // fixup "flattened JSON" to look like "general JSON"
      if (input.signature) {
        input.signatures = [
          {
            protected: input.protected || undefined,
            header: input.header || undefined,
            signature: input.signature
          }
        ];
      }

      // ensure signatories exists
      var sigList = input.signatures || [{}];

      // combine fields and decode signature per signatory
      sigList = sigList.map(function(s) {
        var header = clone(s.header || {});
        var protect = s.protected ?
                      JSON.parse(base64url.decode(s.protected, "utf8")) :
                      {};
        header = merge(header, protect);
        var signature = base64url.decode(s.signature);

        return {
          protected: s.protected,
          header: header,
          signature: signature
        };
      });

      var promise = new Promise(function(resolve, reject) {
        var processSig = function() {
          var sig = sigList.shift();
          if (!sig) {
            reject(new Error("no key found"));
            return;
          }

          var content = new Buffer((sig.protected || "") + "." + input.payload, "ascii");

          var algPromise,
              algKey = keystore.get({
            use: "sig",
            alg: sig.header.alg,
            kid: sig.header.kid
          });
          if (algKey) {
            algPromise = algKey.verify(sig.header.alg,
                                       content,
                                       sig.signature);
          } else {
            algPromise = Promise.reject("key does not match");
          }
          algPromise = algPromise.then(function(result) {
            var payload = result.data.toString("ascii");
            payload = payload.split(".")[1];
            payload = base64url.decode(payload);
            var jws = {
              header: sig.header,
              payload: payload,
              signature: result.mac
            };
            resolve(jws);
          }, processSig);
        };
        processSig();
      });

      return promise;
    }
  });
};

/**
 * @description
 * Creates a new JWS.Verifier with the given Key or KeyStore.
 *
 * @param {JWK.Key|JWK.KeyStore} ks The Key or KeyStore to use for verification.
 * @returns {JWS.Verifier} The new Verifier.
 */
function createVerify(ks) {
  var vfy = new JWSVerifier(ks);

  return vfy;
}

module.exports = {
  verifier: JWSVerifier,
  createVerify: createVerify
};
