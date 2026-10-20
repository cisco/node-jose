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
    },
    {
      alg: "CONCAT-SHA-256",
      desc: "NIST-CAVP SHA-256 multi-block (48 bytes)",
      ikm: "003b84682ef996e462ac04fbf68d19a18fb74f869df87df24cdfcf21e2194784",
      otherInfo: "434156536964a1b2c3d4e5f9b260f9b3a465922bb2191dd60c3c691912f7070c0fc2a47e2485963982fdb486dc626b",
      keyLength: 48,
      okm: "53272dad13352335bc2dc61c7227bdf79fb2c79bff43550911a3a8ff253794b16f360e5271491b3d27f74ddb84aaa6a4"
    },
    {
      alg: "CONCAT-SHA-384",
      desc: "SHA-384 multi-block (64 bytes)",
      ikm: "003b84682ef996e462ac04fbf68d19a18fb74f869df87df24cdfcf21e2194784",
      otherInfo: "434156536964a1b2c3d4e5f9b260f9b3a465922bb2191dd60c3c691912f7070c0fc2a47e2485963982fdb486dc626b",
      keyLength: 64,
      okm: "ab05d7d092bb64916e2945668b38959a4e29fc1c3c9e587551fe0ca5199b1f13c28c1dde834455f5200369ccd06bbe0f635365d439c70c9c6bb09fdafb4f00a8"
    },
    {
      alg: "CONCAT-SHA-512",
      desc: "SHA-512 multi-block (80 bytes)",
      ikm: "003b84682ef996e462ac04fbf68d19a18fb74f869df87df24cdfcf21e2194784",
      otherInfo: "434156536964a1b2c3d4e5f9b260f9b3a465922bb2191dd60c3c691912f7070c0fc2a47e2485963982fdb486dc626b",
      keyLength: 80,
      okm: "ceb36d3d9e44e073a3d78045821a51aa95f81227f7e7b1e63b1121b7d85e60270b305b434c0e6fc76f06a4dd9ee46d7dedd87e47adb9560353317f32e5dbfc24798361b22372bde91a8ef6ab366ebf11"
    }
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
