/*!
 * parse/index.js - JOSE Parser Entry Point
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var compact = require("./compact"),
    json = require("./json");

var parse = module.exports = function(input) {
  if ("string" === typeof input) {
    return compact(input);
  } else if (input) {
    return json(input);
  } else {
    throw new TypeError("invalid input");
  }
};

parse.compact = compact;
parse.json = json;
