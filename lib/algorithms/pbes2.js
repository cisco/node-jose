/*!
 * algorithms/pbes2.js - Password-Based Encryption (v2) Algorithms
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var forge = require("../deps/forge.js"),
    util = require("../util"),
    helpers = require("./helpers.js"),
    CONSTANTS = require("./constants.js"),
    KW = require("./aes-kw.js");

var NULL_BUFFER = new Buffer([0]);

function fixSalt(hmac, kw, salt) {
  var alg = "PBES2-" + hmac + "+" + kw;
  var output = [
    new Buffer(alg, "utf8"),
    NULL_BUFFER,
    salt
  ];
  return Buffer.concat(output);
}

function pbes2EncryptFN(hmac, kw) {
  var keyLen = CONSTANTS.KEYLENGTH[kw] / 8;

  var fallback = function(key, pdata, props) {
    props = props || {};

    var salt = util.asBuffer(props.p2s || new Buffer(0), "base64url"),
        itrs = props.p2c || 0;

    if (0 >= itrs) {
      return Promise.reject(new Error("invalid iteration count"));
    }

    if (8 > salt.length) {
      return Promise.reject(new Error("salt too small"));
    }
    salt = fixSalt(hmac, kw, salt);

    var promise;

    // STEP 1: derive shared key
    promise = new Promise(function(resolve, reject) {
      var md = forge.md[hmac.replace("HS", "SHA").toLowerCase()].create();
      var cb = function(err, dk) {
        if (err) {
          reject(err);
        } else {
          dk = new Buffer(dk, "binary");
          resolve(dk);
        }
      };

      forge.pkcs5.pbkdf2(key.toString("binary"),
                         salt.toString("binary"),
                         itrs,
                         keyLen,
                         md,
                         cb);
    });

    // STEP 2: encrypt cek
    promise = promise.then(function(dk) {
      return KW[kw].encrypt(dk, pdata);
    });
    return promise;
  };

  // NOTE: WebCrypto API missing until there's better support
  var webcrypto = null;

  var nodejs = function(key, pdata, props) {
    if (6 > helpers.nodeCrypto.pbkdf2.length) {
      throw new Error("unsupported algorithm: PBES2-" + hmac + "+" + kw);
    }

    props = props || {};

    var salt = util.asBuffer(props.p2s || new Buffer(0), "base64url"),
        itrs = props.p2c || 0;

    if (0 >= itrs) {
      return Promise.reject(new Error("invalid iteration count"));
    }

    if (8 > salt.length) {
      return Promise.reject(new Error("salt too small"));
    }
    salt = fixSalt(hmac, kw, salt);

    var promise;

    // STEP 1: derive shared key
    var hash = hmac.replace("HS", "SHA");
    promise = new Promise(function(resolve, reject) {
      function cb(err, dk) {
        if (err) {
          reject(err);
        } else {
          resolve(dk);
        }
      }
      helpers.nodeCrypto.pbkdf2(key, salt, itrs, keyLen, hash, cb);
    });

    // STEP 2: encrypt cek
    promise = promise.then(function(dk) {
      return KW[kw].encrypt(dk, pdata);
    });

    return promise;
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

function pbes2DecryptFN(hmac, kw) {
  var keyLen = CONSTANTS.KEYLENGTH[kw] / 8;

  var fallback = function(key, cdata, props) {
    props = props || {};

    var salt = util.asBuffer(props.p2s || new Buffer(0), "base64url"),
        itrs = props.p2c || 0;

    if (0 >= itrs) {
      return Promise.reject(new Error("invalid iteration count"));
    }

    if (8 > salt.length) {
      return Promise.reject(new Error("salt too small"));
    }
    salt = fixSalt(hmac, kw, salt);

    var promise;

    // STEP 1: derived shared key
    promise = new Promise(function(resolve, reject) {
      var md = forge.md[hmac.replace("HS", "SHA").toLowerCase()].create();
      var cb = function(err, dk) {
        if (err) {
          reject(err);
        } else {
          dk = new Buffer(dk, "binary");
          resolve(dk);
        }
      };

      forge.pkcs5.pbkdf2(key.toString("binary"),
                         salt.toString("binary"),
                         itrs,
                         keyLen,
                         md,
                         cb);
    });

    // STEP 2: decrypt cek
    promise = promise.then(function(dk) {
      return KW[kw].decrypt(dk, cdata);
    });
    return promise;
  };

  // NOTE: WebCrypto API missing until there's better support
  var webcrypto = null;

  var nodejs = function(key, cdata, props) {
    if (6 > helpers.nodeCrypto.pbkdf2.length) {
      throw new Error("unsupported algorithm: PBES2-" + hmac + "+" + kw);
    }

    props = props || {};

    var salt = util.asBuffer(props.p2s || new Buffer(0), "base64url"),
        itrs = props.p2c || 0;

    if (0 >= itrs) {
      return Promise.reject(new Error("invalid iteration count"));
    }

    if (8 > salt.length) {
      return Promise.reject(new Error("salt too small"));
    }
    salt = fixSalt(hmac, kw, salt);

    var promise;

    // STEP 1: derive shared key
    var hash = hmac.replace("HS", "SHA");
    promise = new Promise(function(resolve, reject) {
      function cb(err, dk) {
        if (err) {
          reject(err);
        } else {
          resolve(dk);
        }
      }
      helpers.nodeCrypto.pbkdf2(key, salt, itrs, keyLen, hash, cb);
    });

    // STEP 2: decrypt cek
    promise = promise.then(function(dk) {
      return KW[kw].decrypt(dk, cdata);
    });

    return promise;
  };

  return helpers.setupFallback(nodejs, webcrypto, fallback);
}

// ### Public API
// [name].encrypt
// [name].decrypt
var pbes2 = {};
[
  "PBES2-HS256+A128KW",
  "PBES2-HS384+A192KW",
  "PBES2-HS512+A256KW"
].forEach(function(alg) {
  var parts = /PBES2-(HS\d+)\+(A\d+KW)/g.exec(alg);
  var hmac = parts[1],
      kw = parts[2];
  pbes2[alg] = {
    encrypt: pbes2EncryptFN(hmac, kw),
    decrypt: pbes2DecryptFN(hmac, kw)
  };
});

module.exports = pbes2;
