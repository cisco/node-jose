/*!
 * deps/forge.js - Forge Package Customization
 *
 * Copyright (c) 2015 Cisco Systems, Inc.  See LICENSE file.
 */
"use strict";

var forge = {
  aes: require("node-forge/js/aes"),
  asn1: require("node-forge/js/asn1"),
  cipher: require("node-forge/js/cipher"),
  hmac: require("node-forge/js/hmac"),
  jsbn: require("node-forge/js/jsbn"),
  md: require("node-forge/js/md"),
  mgf: require("node-forge/js/mgf"),
  pem: require("node-forge/js/pem"),
  pkcs1: require("node-forge/js/pkcs1"),
  pkcs5: require("node-forge/js/pkcs5"),
  pkcs7: require("node-forge/js/pkcs7"),
  pki: require("node-forge/js/x509"),
  prime: require("node-forge/js/prime"),
  prng: require("node-forge/js/prng"),
  pss: require("node-forge/js/pss"),
  random: require("node-forge/js/random"),
  util: require("node-forge/js/util")
};

// load hash algorithms
require("node-forge/js/sha1");
require("node-forge/js/sha256");
require("node-forge/js/sha512");

// load symmetric cipherModes
require("node-forge/js/cipherModes");

// load AES cipher suites
// TODO: move this to a separate file
require("node-forge/js/aesCipherSuites");

// Define AES "raw" cipher mode
function modeRaw(options) {
  options = options || {};
  this.name = "";
  this.cipher = options.cipher;
  this.blockSize = options.blockSize || 16;
  this._blocks = this.blockSize / 4;
  this._inBlock = new Array(this._blocks);
  this._outBlock = new Array(this._blocks);
}

modeRaw.prototype.start = function() {};

modeRaw.prototype.encrypt = function(input, output) {
  var i;

  // get next block
  for(i = 0; i < this._blocks; ++i) {
    this._inBlock[i] = input.getInt32();
  }

  // encrypt block
  this.cipher.encrypt(this._inBlock, this._outBlock);

  // write output
  for(i = 0; i < this._blocks; ++i) {
    output.putInt32(this._outBlock[i]);
  }
};

modeRaw.prototype.decrypt = function(input, output) {
  var i;

  // get next block
  for(i = 0; i < this._blocks; ++i) {
    this._inBlock[i] = input.getInt32();
  }

  // decrypt block
  this.cipher.decrypt(this._inBlock, this._outBlock);

  // write output
  for(i = 0; i < this._blocks; ++i) {
    output.putInt32(this._outBlock[i]);
  }
};

(function() {
  var name = "AES",
      mode = modeRaw,
      factory;
  factory = function() { return new forge.aes.Algorithm(name, mode); };
  forge.cipher.registerAlgorithm(name, factory);
})();

// Redefine util.setImmediate(cb) to always be util.nextTick(cb)
(function() {
  if (forge.util.nextTick !== forge.util.setImmediate) {
    forge.util.setImmediate = forge.util.nextTick;
  }
})();

module.exports = forge;
