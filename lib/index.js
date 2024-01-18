/*!
 * index.js - Main Entry Point
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

if (typeof Promise === "undefined") {
  require("es6-promise").polyfill();
}

if (typeof Buffer === "undefined") {
  (global || window).Buffer = require("buffer").Buffer;
}

if (typeof process === "undefined") {
  (global || window).process = require("process");
}

if (!process.version) {
  process.version = "";
}

var JWS = require("./jws");

module.exports = {
  JWA: require("./algorithms"),
  JWE: require("./jwe"),
  JWK: require("./jwk"),
  JWS: JWS,
  util: require("./util"),
  base64url: require("./util/base64url"),
  utf8: require("./util/utf8"),
  parse: require("./parse"),
  canYouSee: JWS.createVerify
};
