/*!
 * index.js - Main Entry Point
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

if (typeof Promise === "undefined") {
  require("es6-promise").polyfill();
}
var global = global || window;
// Browser Support: make node's Buffer API available globally n the browser
global.Buffer = global.Buffer || require("buffer").Buffer;
// Browser Support: make node's Process API available globally n the browser
global.process = global.process || require("process");

var JWS = require("./jws");

module.exports = {
  JWA: require("./algorithms"),
  JWE: require("./jwe"),
  JWK: require("./jwk"),
  JWS: JWS,
  util: require("./util"),
  parse: require("./parse"),
  canYouSee: JWS.createVerify
};
