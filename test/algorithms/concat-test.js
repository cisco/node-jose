/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/concat", function() {
  var vectors = [
    {
      alg: "CONCAT-SHA-256",
      desc: "NIST-CAVP SHA-256",
      ikm: "003b84682ef996e462ac04fbf68d19a18fb74f869df87df24cdfcf21e2194784",
      otherInfo: "434156536964a1b2c3d4e5f9b260f9b3a465922bb2191dd60c3c691912f7070c0fc2a47e2485963982fdb486dc626b",
      keyLength: 16,
      okm: "53272dad13352335bc2dc61c7227bdf7"
    }
    // TODO: tests for other SHA2 algorithms
  ];

  vectors.forEach(function(v) {
    var deriverunner = function() {
      var ikm = Buffer.from(v.ikm, "hex"),
          okm = Buffer.from(v.okm, "hex");

      var props = {};
      if (v.otherInfo) {
        props.otherInfo = Buffer.from(v.otherInfo, "hex");
      }
      props.length = v.keyLength;

      var promise = algorithms.derive(v.alg, ikm, props);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), okm.toString("hex"));
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") derivation", deriverunner);
  });
});
