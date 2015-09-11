/*!
 * algorithms/aes-cbc-hmac-sha2.js - AES-CBC-HMAC-SHA2 Composited Encryption
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var helpers = require("./helpers.js"),
    HMAC = require("./hmac.js"),
    forge = require("../deps/forge.js"),
    DataBuffer = require("../util/databuffer.js");

function cbcHmacEncryptFN(size) {
  function commonChecks(key, iv) {
    if ((size << 1) !== (key.length << 3)) {
      throw new Error("invalid key size");
    }
    if (16 !== iv.length) {
      throw new Error("invalid iv");
    }
  }

  function doHmacTag(key, iv, cdata, adata) {
    var promise;
    // construct MAC input
    var mdata = Buffer.concat([
      adata,
      iv,
      cdata,
      helpers.int64ToBuffer(adata.length * 8)
    ]);
    promise = HMAC["HS" + (size * 2)].sign(key, mdata, {
      loose: true
    });
    promise = promise.then(function(result) {
      // TODO: move slice to hmac.js
      var tag = result.mac.slice(0, size / 8);
      return {
        data: cdata,
        tag: tag
      };
    });
    return promise;
  }

  // ### 'fallback' implementation -- uses forge
  var fallback = function(key, pdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0);

    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve();

    // STEP 1 -- Encrypt
    promise = promise.then(function() {
      var encKey = key.slice(size / 8);

      var cipher = forge.cipher.createCipher("AES-CBC", new DataBuffer(encKey));
      cipher.start({
        iv: new DataBuffer(iv)
      });

      // TODO: chunk data
      cipher.update(new DataBuffer(pdata));
      if (!cipher.finish()) {
        return Promise.reject(new Error("encryption failed"));
      }

      var cdata = cipher.output.native();
      return cdata;
    });

    // STEP 2 -- MAC
    promise = promise.then(function(cdata) {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata);
    });

    return promise;
  };

  // ### WebCryptoAPI implementation
  // TODO: cache CryptoKey sooner
  var webcrypto = function(key, pdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0);

    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve();

    // STEP 1 -- Encrypt
    promise = promise.then(function() {
      var alg = {
        name: "AES-CBC"
      };
      var encKey = key.slice(size / 8);
      return helpers.subtleCrypto.importKey("raw", encKey, alg, true, ["encrypt"]);
    });
    promise = promise.then(function(key) {
      var alg = {
        name: "AES-CBC",
        iv: iv
      };
      return helpers.subtleCrypto.encrypt(alg, key, pdata);
    });
    promise = promise.then(function(cdata) {
      // wrap in *augmented* Uint8Array -- Buffer without copies
      cdata = new Uint8Array(cdata);
      cdata = Buffer._augment(cdata);
      return cdata;
    });

    // STEP 2 -- MAC
    promise = promise.then(function(cdata) {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata);
    });
    return promise;
  };

  // ### NodeJS implementation
  var nodejs = function(key, pdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0);

    try {
      commonChecks(key, iv, adata);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve(pdata);

    // STEP 1 -- Encrypt
    promise = promise.then(function(pdata) {
      var encKey = key.slice(size / 8),
          name = "AES-" + size + "-CBC";
      var cipher = helpers.nodeCrypto.createCipheriv(name, encKey, iv);
      var cdata = Buffer.concat([
        cipher.update(pdata),
        cipher.final()
      ]);
      return cdata;
    });

    // STEP 2 -- MAC
    promise = promise.then(function(cdata) {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata);
    });

    return promise;
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

function cbcHmacDecryptFN(size) {
  function commonChecks(key, iv, tag) {
    if ((size << 1) !== (key.length << 3)) {
      throw new Error("invalid key size");
    }
    if (16 !== iv.length) {
      throw new Error("invalid iv");
    }
    if ((size >>> 3) !== tag.length) {
      throw new Error("invalid tag length");
    }
  }

  function doHmacTag(key, iv, cdata, adata, tag) {
    var promise;
    // construct MAC input
    var mdata = Buffer.concat([
      adata,
      iv,
      cdata,
      helpers.int64ToBuffer(adata.length * 8)
    ]);
    promise = HMAC["HS" + (size * 2)].verify(key, mdata, tag, {
      loose: true
    });
    promise = promise.then(function() {
      // success -- return ciphertext
      return cdata;
    }, function() {
      // failure -- invalid tag error
      throw new Error("mac check failed");
    });
    return promise;
  }

  // ### 'fallback' implementation -- uses forge
  var fallback = function(key, cdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0),
        tag = props.tag || props.mac || new Buffer(0);

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve();

    // STEP 1 -- MAC
    promise = promise.then(function() {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata, tag);
    });

    // STEP 2 -- Decrypt
    promise = promise.then(function() {
      var encKey = key.slice(size / 8);

      var cipher = forge.cipher.createDecipher("AES-CBC", new DataBuffer(encKey));
      cipher.start({
        iv: new DataBuffer(iv)
      });

      // TODO: chunk data
      cipher.update(new DataBuffer(cdata));
      if (!cipher.finish()) {
        return Promise.reject(new Error("encryption failed"));
      }

      var pdata = cipher.output.native();
      return pdata;
    });

    return promise;
  };

  // ### WebCryptoAPI implementation
  // TODO: cache CryptoKey sooner
  var webcrypto = function(key, cdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0),
        tag = props.tag || props.mac || new Buffer(0);

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve();

    // STEP 1 -- MAC
    promise = promise.then(function() {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata, tag);
    });

    // STEP 2 -- Decrypt
    promise = promise.then(function() {
      var alg = {
        name: "AES-CBC"
      };
      var encKey = key.slice(size / 8);
      return helpers.subtleCrypto.importKey("raw", encKey, alg, true, ["decrypt"]);
    });
    promise = promise.then(function(key) {
      var alg = {
        name: "AES-CBC",
        iv: iv
      };
      return helpers.subtleCrypto.decrypt(alg, key, cdata);
    });
    promise = promise.then(function(pdata) {
      // wrap in *augmented* Uint8Array -- Buffer without copies
      pdata = new Uint8Array(pdata);
      pdata = Buffer._augment(pdata);
      return pdata;
    });

    return promise;
  };

  // ### NodeJS implementation
  var nodejs = function(key, cdata, props) {
    props = props || {};

    var iv = props.iv || new Buffer(0),
        adata = props.aad || props.adata || new Buffer(0),
        tag = props.tag || props.mac || new Buffer(0);

    // validate inputs
    try {
      commonChecks(key, iv, tag);
    } catch (err) {
      return Promise.reject(err);
    }

    var promise = Promise.resolve();

    // STEP 1 -- MAC
    promise = promise.then(function() {
      var macKey = key.slice(0, size / 8);
      return doHmacTag(macKey, iv, cdata, adata, tag);
    });

    // SETP 2 -- Decrypt
    promise = promise.then(function(cdata) {
      var encKey = key.slice(size / 8),
          name = "AES-" + size + "-CBC";
      var cipher = helpers.nodeCrypto.createDecipheriv(name, encKey, iv);
      var pdata = Buffer.concat([
        cipher.update(cdata),
        cipher.final()
      ]);
      return pdata;
    });

    return promise;
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

// ### Public API
// * [name].encrypt
// * [name].decrypt
var aesCbcHmacSha2 = {};
[
  "A128CBC-HS256",
  "A192CBC-HS384",
  "A256CBC-HS512"
].forEach(function(alg) {
  var size = parseInt(/A(\d+)CBC-HS(\d+)?/g.exec(alg)[1]);
  aesCbcHmacSha2[alg] = {
    encrypt: cbcHmacEncryptFN(size),
    decrypt: cbcHmacDecryptFN(size)
  };
});

module.exports = aesCbcHmacSha2;
