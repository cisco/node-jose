/*!
 * algorithms/aes-gcm.js - AES-GCM Encryption and Key-Wrapping
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var helpers = require("./helpers.js"),
    util = require("../util"),
    CONSTANTS = require("./constants.js"),
    GCM = require("../deps/ciphermodes/gcm");

function gcmEncryptFN(size, wrap) {
  function commonChecks(key, iv) {
    if (size !== (key.length << 3)) {
       throw new Error("invalid key size");
    }
    if (!iv && !wrap) {
      throw new Error("invalid iv");
    }
    if (iv && 12 !== iv.length) {
      throw new Error("invalid iv");
    }
  }

  function prepareResults(results) {
    if (wrap) {
      var iv = util.base64url.encode(results.iv);
      var tag = util.base64url.encode(results.tag);

      results = {
        data: results.data,
        header: {
          iv: iv,
          tag: tag
        }
      };
    }

    return results;
  }

  // ### 'fallback' implementation -- uses forge
  var fallback = function(key, pdata, props) {
    var iv = props.iv,
        adata = props.aad || props.adata || Buffer.alloc(0),
        cipher,
        cdata;

    // validate inputs
    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    iv = iv || util.randomBytes(12);

    // setup cipher
    cipher = GCM.createCipher({
      key: key,
      iv: iv,
      additionalData: adata
    });
    // ciphertext is the same length as plaintext
    cdata = Buffer.alloc(pdata.length);

    var promise = new Promise(function(resolve, reject) {
      var amt = CONSTANTS.CHUNK_SIZE,
          clen = 0,
          poff = 0;

      (function doChunk() {
        var plen = Math.min(amt, pdata.length - poff);
        clen += cipher.update(pdata,
                              poff,
                              plen,
                              cdata,
                              clen);
        poff += plen;
        if (pdata.length > poff) {
          setTimeout(doChunk, 0);
          return;
        }

        // finish it
        clen += cipher.finish(cdata, clen);
        if (clen !== pdata.length) {
          reject(new Error("encryption failed"));
          return;
        }

        // resolve with output
        var tag = cipher.tag;
        resolve(prepareResults({
          data: cdata,
          iv: iv,
          tag: tag
        }));
      })();
    });

    return promise;
  };

  // ### WebCryptoAPI implementation
  // TODO: cache CryptoKey sooner
  var webcrypto = function(key, pdata, props) {
    var iv = props.iv,
        adata = props.aad || props.adata || Buffer.alloc(0);

    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    iv = iv || util.randomBytes(12);

    var alg = {
      name: "AES-GCM"
    };
    var promise;
    promise = helpers.subtleCrypto.importKey("raw", key, alg, true, ["encrypt"]);
    promise = promise.then(function(key) {
      alg.iv = iv;
      alg.tagLength = 128;
      if (adata.length) {
        alg.additionalData = adata;
      }

      return helpers.subtleCrypto.encrypt(alg, key, pdata);
    });
    promise = promise.then(function(result) {
      var tagStart = result.byteLength - 16;

      var tag = result.slice(tagStart);
      tag = Buffer.from(tag);

      var cdata = result.slice(0, tagStart);
      cdata = Buffer.from(cdata);

      return prepareResults({
        data: cdata,
        iv: iv,
        tag: tag
      });
    });

    return promise;
  };

  // ### NodeJS implementation
  var nodejs = function(key, pdata, props) {
    var iv = props.iv,
        adata = props.aad || props.adata || Buffer.alloc(0);

    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    iv = iv || util.randomBytes(12);

    var alg = "aes-" + (key.length * 8) + "-gcm";
    var cipher;
    try {
      cipher = helpers.nodeCrypto.createCipheriv(alg, key, iv);
    } catch (err) {
      throw new Error("unsupported algorithm: " + alg);
    }
    if ("function" !== typeof cipher.setAAD) {
      throw new Error("unsupported algorithm: " + alg);
    }
    if (adata.length) {
      cipher.setAAD(adata);
    }

    var cdata = Buffer.concat([
      cipher.update(pdata),
      cipher.final()
    ]);
    var tag = cipher.getAuthTag();

    return prepareResults({
      data: cdata,
      iv: iv,
      tag: tag
    });
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

function gcmDecryptFN(size) {
  function commonChecks(key, iv, tag) {
    if (size !== (key.length << 3)) {
      throw new Error("invalid key size");
    }
    if (12 !== iv.length) {
      throw new Error("invalid iv");
    }
    if (16 !== tag.length) {
      throw new Error("invalid tag length");
    }
  }

  // ### fallback implementation -- uses forge
  var fallback = function(key, cdata, props) {
    var adata = props.aad || props.adata || Buffer.alloc(0),
        iv = props.iv || Buffer.alloc(0),
        tag = props.tag || props.mac || Buffer.alloc(0),
        cipher,
        pdata;

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    // setup cipher
    cipher = GCM.createDecipher({
      key: key,
      iv: iv,
      additionalData: adata,
      tag: tag
    });
    // plaintext is the same length as ciphertext
    pdata = Buffer.alloc(cdata.length);

    var promise = new Promise(function(resolve, reject) {
      var amt = CONSTANTS.CHUNK_SIZE,
          plen = 0,
          coff = 0;

      (function doChunk() {
        var clen = Math.min(amt, cdata.length - coff);
        plen += cipher.update(cdata,
                              coff,
                              clen,
                              pdata,
                              plen);
        coff += clen;
        if (cdata.length > coff) {
          setTimeout(doChunk, 0);
          return;
        }

        try {
          plen += cipher.finish(pdata, plen);
        } catch (err) {
          reject(new Error("decryption failed"));
          return;
        }

        if (plen !== cdata.length) {
          reject(new Error("decryption failed"));
          return;
        }

        // resolve with output
        resolve(pdata);
      })();
    });

    return promise;
  };

  // ### WebCryptoAPI implementation
  // TODO: cache CryptoKey sooner
  var webcrypto = function(key, cdata, props) {
    var adata = props.aad || props.adata || Buffer.alloc(0),
        iv = props.iv || Buffer.alloc(0),
        tag = props.tag || props.mac || Buffer.alloc(0);

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    var alg = {
      name: "AES-GCM"
    };
    var promise;
    promise = helpers.subtleCrypto.importKey("raw", key, alg, true, ["decrypt"]);
    promise = promise.then(function(key) {
      alg.iv = iv;
      alg.tagLength = 128;
      if (adata.length) {
        alg.additionalData = adata;
      }

      // concatenate cdata and tag
      cdata = Buffer.concat([cdata, tag], cdata.length + tag.length);

      return helpers.subtleCrypto.decrypt(alg, key, cdata);
    });
    promise = promise.then(function(pdata) {
      pdata = Buffer.from(pdata);
      return pdata;
    });

    return promise;
  };

  var nodejs = function(key, cdata, props) {
    var adata = props.aad || props.adata || Buffer.alloc(0),
        iv = props.iv || Buffer.alloc(0),
        tag = props.tag || props.mac || Buffer.alloc(0);

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    var alg = "aes-" + (key.length * 8) + "-gcm";
    var cipher;
    try {
      cipher = helpers.nodeCrypto.createDecipheriv(alg, key, iv);
    } catch(err) {
      throw new Error("unsupported algorithm: " + alg);
    }
    if ("function" !== typeof cipher.setAAD) {
      throw new Error("unsupported algorithm: " + alg);
    }
    cipher.setAuthTag(tag);
    if (adata.length) {
      cipher.setAAD(adata);
    }

    try {
      var pdata = Buffer.concat([
        cipher.update(cdata),
        cipher.final()
      ]);

      return pdata;
    } catch (err) {
      throw new Error("decryption failed");
    }
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

// ### Public API
// * [name].encrypt
// * [name].decrypt
var aesGcm = {};
[
  "A128GCM",
  "A192GCM",
  "A256GCM",
  "A128GCMKW",
  "A192GCMKW",
  "A256GCMKW"
].forEach(function(alg) {
  var parts = /A(\d+)GCM(KW)?/g.exec(alg);
  var size = parseInt(parts[1]);
  var wrap = (parts[2] === "KW");
  aesGcm[alg] = {
    encrypt: gcmEncryptFN(size, wrap),
    decrypt: gcmDecryptFN(size, wrap)
  };
});

module.exports = aesGcm;
