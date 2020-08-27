/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var cloneDeep = require("lodash/cloneDeep");
var forEach = require("lodash/forEach")
var chai = require("chai");

var JWE = require("../../lib/jwe"),
    JWK = require("../../lib/jwk"),
    util = require("../../lib/util");

var assert = chai.assert;

var fixtures = {
  "5_2.key_encryption_using_rsa-oaep_with_aes-gcm": cloneDeep(require("jose-cookbook/jwe/5_2.key_encryption_using_rsa-oaep_with_aes-gcm.json")),
  "5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2": cloneDeep(require("jose-cookbook/jwe/5_3.key_wrap_using_pbes2-aes-keywrap_with-aes-cbc-hmac-sha2.json")),
  "5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm": cloneDeep(require("jose-cookbook/jwe/5_4.key_agreement_with_key_wrapping_using_ecdh-es_and_aes-keywrap_with_aes-gcm.json")),
  "5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2": cloneDeep(require("jose-cookbook/jwe/5_5.key_agreement_using_ecdh-es_with_aes-cbc-hmac-sha2.json")),
  "5_6.direct_encryption_using_aes-gcm": cloneDeep(require("jose-cookbook/jwe/5_6.direct_encryption_using_aes-gcm.json")),
  "5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json": cloneDeep(require("jose-cookbook/jwe/5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json")),
  "5_8.key_wrap_using_aes-keywrap_with_aes-gcm": cloneDeep(require("jose-cookbook/jwe/5_8.key_wrap_using_aes-keywrap_with_aes-gcm.json")),
  "5_9.compressed_content": cloneDeep(require("jose-cookbook/jwe/5_9.compressed_content.json")),
  "5_10.including_additional_authentication_data": cloneDeep(require("jose-cookbook/jwe/5_10.including_additional_authentication_data.json"))
  /*
  //*/
};

describe("jwe", function() {
  forEach(fixtures, function(fixture) {
    var input = fixture.input;
    var generated = fixture.generated;
    var encrypting = fixture.encrypting_content;
    var output = fixture.output;

    describe(fixture.title, function() {
      before(function keyToJWK() {
        var prep = [],
            promise;

        if (input.key) {
          // Coerce the key object to a JWK object
          promise = JWK.asKey(input.key);
          promise = promise.then(function(key) {
            input.key = key;
            assert(JWK.isKey(input.key));
          });
          prep.push(promise);
        }
        if (input.pwd) {
          // Coerce password to JWK object
          promise = JWK.asKey({
            kty: "oct",
            k: util.base64url.encode(input.pwd, "utf8")
          });
          promise = promise.then(function(key) {
            input.key = key;
            assert(JWK.isKey(input.key));
          });
        }
        // Coerce the CEK to a JWK object
        if (generated.cek) {
          promise = JWK.asKey({
            kty: "oct",
            k: generated.cek
          });
          promise = promise.then(function(key) {
            generated.cek = key;
            assert(JWK.isKey(generated.cek));
          });
          prep.push(promise);
        }

        return Promise.all(prep);
      });

      // encrypting
      if (fixture.reproducible) {
        if (output.compact) {
          it("encrypts to a compact JWE", function() {
            var options = {
              compact: true,
              contentAlg: input.enc,
              protect: Object.keys(encrypting.protected),
              iv: generated.iv,
              fields: encrypting.protected
            };
            if (generated.cek) {
              options.cek = generated.cek;
            }
            if (input.aad) {
              options.aad = input.aad;
            }

            var encrypter = JWE.createEncrypt(options, {
              key: input.key,
              reference: false
            });
            return encrypter.final(input.plaintext, "utf8")
              .then(function(ciphertext) {
                assert.deepEqual(ciphertext, output.compact);
              });
          });
        }
        if (output.json) {
          it("encrypts to a general JSON JWE", function() {
            var options = {
              compact: false,
              contentAlg: input.enc,
              protect: Object.keys(encrypting.protected),
              iv: generated.iv,
              fields: encrypting.protected
            };
            if (generated.cek) {
              options.cek = generated.cek;
            }
            if (input.aad) {
              options.aad = input.aad;
            }

            var encrypter = JWE.createEncrypt(options, {
              key: input.key,
              reference: false
            });
            return encrypter.final(input.plaintext, "utf8")
              .then(function(ciphertext) {
                assert.deepEqual(ciphertext, output.json);
              });
          });
        }
        if (output.json_flat) {
          it("encrypts to a flattened JSON JWE", function() {
            var options = {
              format: "flattened",
              contentAlg: input.enc,
              protect: Object.keys(encrypting.protected),
              iv: generated.iv,
              fields: encrypting.protected
            };
            if (generated.cek) {
              options.cek = generated.cek;
            }
            if (input.aad) {
              options.aad = input.aad;
            }

            var encrypter = JWE.createEncrypt(options, {
              key: input.key,
              reference: false
            });
            return encrypter.final(input.plaintext, "utf8")
              .then(function(ciphertext) {
                assert.deepEqual(ciphertext, output.json_flat);
              });
          });
        }
      }

      if (output.compact) {
        it("decrypts from a compact JWE", function() {
          var decrypter = JWE.createDecrypt(input.key);
          return decrypter.decrypt(output.compact)
            .then(function(result) {
              // result.plaintext is a buffer, assert.equal will invoke its
              // toString() method implicitly
              assert.equal(result.payload, input.plaintext);

              // But let's make it clear that result.plaintext needs to be
              // converted before actually being a string.
              var plaintext = result.payload.toString();
              assert.deepEqual(plaintext, input.plaintext);

              // Verify that plaintext and payload are the same thing
              assert.equal(result.plaintext, result.payload);
            });
        });
      }
      if (output.json) {
        it("decrypts from a general JSON JWE", function() {
          var decrypter = JWE.createDecrypt(input.key);
          return decrypter.decrypt(output.json)
            .then(function(result) {
              // result.plaintext is a buffer, assert.equal will invoke its
              // toString() method implicitly
              assert.equal(result.plaintext, input.plaintext);

              // But let's make it clear that result.plaintext needs to be
              // converted before actually being a string.
              var plaintext = result.plaintext.toString();
              assert.deepEqual(plaintext, input.plaintext);

              // Verify that plaintext and payload are the same thing
              assert.equal(result.plaintext, result.payload);
            });
        });
      }
      if (output.json_flat) {
        it("decrypts from a flattened JSON JWE", function() {
          var decrypter = JWE.createDecrypt(input.key);
          return decrypter.decrypt(output.json_flat)
            .then(function(result) {
              // result.plaintext is a buffer, assert.equal will invoke its
              // toString() method implicitly
              assert.equal(result.plaintext, input.plaintext);

              // But let's make it clear that result.plaintext needs to be
              // converted before actually being a string.
              var plaintext = result.plaintext.toString();
              assert.deepEqual(plaintext, input.plaintext);

              // Verify that plaintext and payload are the same thing
              assert.equal(result.plaintext, result.payload);
            });
        });
      }
    });

  });
});
