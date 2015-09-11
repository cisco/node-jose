/*!
 * jwe/decrypt.js - Decrypt from a JWE
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var assign = require("lodash.assign"),
    base64url = require("../util/base64url"),
    JWK = require("../jwk"),
    zlib = require("zlib");

/**
 * @class JWE.Decrypter
 * @classdesc Processor of encrypted data.
 *
 * @description
 * **NOTE:** This class cannot be instantiated directly. Instead
 * call {@link JWE.createDecrypt}.
 */
function JWEDecrypter(ks) {
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

  Object.defineProperty(this, "decrypt", {
    value: function(input) {
      /* eslint camelcase: [0] */
      if (typeof input === "string") {
        input = input.split(".");
        input = {
          protected: input[0],
          recipients: [
            {
              encrypted_key: input[1]
            }
          ],
          iv: input[2],
          ciphertext: input[3],
          tag: input[4]
        };
      } else if (!input || typeof input !== "object") {
        throw new Error("invalid input");
      }
      if ("encrypted_key" in input) {
        input.recipients = [
          {
            encrypted_key: input.encrypted_key
          }
        ];
      }

      // ensure recipients exists
      var rcptList = input.recipients || [{}];

      //combine fields
      var fields;
      fields = input.protected ?
           JSON.parse(base64url.decode(input.protected, "binary")) :
           {};
      fields = assign(input.unprotected || {}, fields);
      rcptList = rcptList.map(function(r) {
        var promise = Promise.resolve();
        var header = r.header || {};
        header = assign(header, fields);
        r.header = header;
        if (header.epk) {
          promise = promise.then(function() {
            return JWK.asKey(header.epk);
          });
          promise = promise.then(function(epk) {
            header.epk = epk.toObject(false);
          });
        }
        return promise.then(function() {
          return r;
        });
      });

      var promise = Promise.all(rcptList);

      // decrypt with first key found
      var algKey,
        encKey;
      promise = promise.then(function(rcptList) {
        var jwe = {};
        return new Promise(function(resolve, reject) {
          var processKey = function() {
            var rcpt = rcptList.shift();
            if (!rcpt) {
              reject(new Error("no key found"));
              return;
            }

            var algPromise,
              prekey;

            prekey = rcpt.encrypted_key || "";
            prekey = base64url.decode(prekey);
            algKey = keystore.get({
              use: "enc",
              alg: rcpt.header.alg,
              kid: rcpt.header.kid
            });
            if (algKey) {
              algPromise = algKey.unwrap(rcpt.header.alg, prekey, rcpt.header);
            } else {
              algPromise = Promise.reject();
            }
            algPromise.then(function(key) {
              encKey = {
                "kty": "oct",
                "k": base64url.encode(key)
              };
              encKey = JWK.asKey(encKey);
              jwe.key = algKey;
              jwe.header = rcpt.header;
              resolve(jwe);
            }, processKey);
          };
          processKey();
        });
      });

      // prepare decipher inputs
      promise = promise.then(function(jwe) {
        jwe.iv = input.iv;
        jwe.tag = input.tag;
        jwe.ciphertext = base64url.decode(input.ciphertext);

        return jwe;
      });

      // decrypt it!
      promise = promise.then(function(jwe) {
        var adata = input.protected;
        if ("aad" in input && null != input.aad) {
          adata += "." + input.aad;
        }
        var params = {
          iv: jwe.iv,
          adata: adata,
          tag: jwe.tag
        };
        var cdata = jwe.ciphertext;

        delete jwe.iv;
        delete jwe.tag;
        delete jwe.ciphertext;

        return encKey.
          then(function(enkKey) {
            return enkKey.decrypt(jwe.header.enc, cdata, params).
              then(function(pdata) {
                jwe.plaintext = pdata;
                return jwe;
              });
          });
      });

      // (OPTIONAL) decompress plaintext
      if (fields.zip === "DEF") {
        promise = promise.then(function(jwe) {
          return new Promise(function(resolve, reject) {
            zlib.inflateRaw(new Buffer(jwe.plaintext), function(err, data) {
              if (err) {
                reject(err);
              }
              else {
                jwe.plaintext = data;
                resolve(jwe);
              }
            });
          });
        });
      }

      return promise;
    }
  });
}

/**
 * @description
 * Creates a new Decrypter for the given Key or KeyStore.
 *
 * @param {JWK.Key|JWK.KeyStore} ks The Key or KeyStore to use for decryption.
 * @returns {JWE.Decrypter} The new Decrypter.
 */
function createDecrypt(ks) {
  var dec = new JWEDecrypter(ks);
  return dec;
}

module.exports = {
  decrypter: JWEDecrypter,
  createDecrypt: createDecrypt
};
