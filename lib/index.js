/*!
 * index.js - Main Entry Point
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

if (typeof Promise === "undefined") {
  require("es6-promise").polyfill();
}

try {   // for browsers
  var global = global || window;
  // Browser Support: make buffer, that emulates node's Buffer API, available globally in the browser
  global.Buffer = global.Buffer || require("buffer").Buffer;
  // Browser Support: make process, that emulates node's Process API, available globally in the browser
  global.process = global.process || require("process");
}
catch (e) {
    // "window is not defined" for node.js
}


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
