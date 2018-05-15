/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/dir", function() {
  var vectors = [
    {
      alg: "dir/128",
      desc: "direct 128-bit key",
      key: "e98b72a9881a84ca6b76e0f43e68647a"
    },
    {
      alg: "dir/192",
      desc: "direct 192-bit key",
      key: "7a7c5b6a8a9ab5acae34a9f6e41f19a971f9c330023c0f0c"
    },
    {
      alg: "dir/256",
      desc: "direct 256-bit key",
      key: "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8"
    }
  ];

  vectors.forEach(function(v) {
    var encRunner = function() {
      var key = Buffer.from(v.key, "hex");

      var promise = algorithms.encrypt("dir", key);
      promise = promise.then(function(result) {
        assert.deepEqual(result.data, key);
        assert.equal(result.once, true);
        assert.equal(result.direct, true);
      });
      return promise;
    };
    var decRunner = function() {
      var key = Buffer.from(v.key, "hex");

      var promise = algorithms.decrypt("dir", key);
      promise = promise.then(function(result) {
        assert.deepEqual(result, key);
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") encryption", encRunner);
    it("performs " + v.alg + " (" + v.desc + ") decryption", decRunner);
  });
});
