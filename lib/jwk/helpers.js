/*!
 * jwk/helpers.js - JWK Internal Helper Functions and Constants
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var clone = require("lodash.clone"),
    util = require("../util");

module.exports = {
  unpackProps: function(props, allowed) {
    var output;

    // apply all of the existing values
    allowed.forEach(function(cfg) {
      if (!(cfg.name in props)) {
        return;
      }
      output = output || {};
      var value = props[cfg.name];
      switch (cfg.type) {
        case "binary":
          if (Buffer.isBuffer(value)) {
            value = value;
            props[cfg.name] = util.base64url.encode(value);
          } else {
            value = util.base64url.decode(value);
          }
          break;
        case "string":
        case "number":
        case "boolean":
          value = value;
          break;
        case "array":
          value = [].concat(value);
          break;
        case "object":
          value = clone(value);
          break;
        default:
          // TODO: deep clone?
          value = value;
          break;
      }
      output[cfg.name] = value;
    });

    // remove any from json that didn't apply
    var check = output || {};
    Object.keys(props).
           forEach(function(n) {
              if (n in check) { return; }
              delete props[n];
           });

    return output;
  },
  COMMON_PROPS: [
    {name: "kty", type: "string"},
    {name: "kid", type: "string"},
    {name: "use", type: "string"},
    {name: "alg", type: "string"},
    {name: "x5c", type: "array"},
    {name: "x5t", type: "binary"},
    {name: "x5u", type: "string"},
    {name: "key_ops", type: "array"}
  ]
};
