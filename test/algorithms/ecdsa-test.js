/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;
var isSafari = require("is-safari");

var algorithms = require("../../lib/algorithms/"),
    util = require("../../lib/util");

function shouldSkip(vector) {
  if ("ES512" !== vector.alg) {
    return false;
  }

  return isSafari;
}

describe("algorithms/ecdsa", function() {
  var vectors = [
    {
      alg: "ES256",
      desc: "ECDSA using P-256 and SHA-256",
      key: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("qE8xuhpJ1HqyRbLg1XR8Wz8Qe_8gU5zmVr9FZqYw6N4"),
        y: util.base64url.decode("_fcR8gSgFQvBi2UoodFtFi61Fu_VQIbf0RjN33y6dzU"),
        d: util.base64url.decode("ALqZCAHDK3jcCGYZOPcqvWIivb2ph46qBq0L1Mdu3Jc")
      },
      msg: util.base64url.decode("d50euE-ihMN9KdXhedADBrQTxEqACgd-WYU_YwX5Lln7f4E")
    },
    {
      alg: "ES384",
      desc: "ECDSA using P-384 and SHA-384",
      key: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("DQgF9mGaYUrhMT5K1y5VZQG_1XAKSGj2G1EdI3aV95DYafNByFqOVeKjSYIFu_0u"),
        y: util.base64url.decode("KaZKhidOZF_DhxuReE5_41Lpg1Hj8RTyTJlM1T_rJntmfCZzmUlOUa2coFERkEvc"),
        d: util.base64url.decode("zyZc5_XuFQ4uHSwJfWwSI-Uzuay2e25c4G2OikNKHt9HdCkEGTe5PqeG4jYuEg5D")
      },
      msg: util.base64url.decode("ISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISE")
    },
    {
      alg: "ES512",
      desc: "ECDSA using P-521 and SHA-512",
      key: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("Ad_BZ3QfGOrkR7UyFeyRnVxYyFm917v1Y5QfJdsTmSVoVqU7kbcZj23VhYyuyMqwRdVeeV7ihYYcl1EGc5Erbk4J"),
        y: util.base64url.decode("AKW1CZRP2Wq3cskiWaSU1ci9m-D5EDifKkva3-4WrsBVqavKoBnx6_U42khxLAuclpwRkxIam49zQ_yE5eCUMf-O"),
        d: util.base64url.decode("Ae9d4Om78X33TBerpl0Ik5vYXNrcj8kx5GWQ6A2oFTVGuZnLcw5r-CeGx-5qm58Klh8casqxaa9KCdVxMZ03kcPL")
      },
      msg: util.base64url.decode("MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE")
    }
  ];

  vectors.forEach(function(v) {
    if (shouldSkip(v)) {
      return;
    }

    // NOTE: The best we can really do is consistency checks
    it("performs " + v.alg + " (" + v.desc + ") sign+verify consistency", function() {
        var key = v.key,
            msg = v.msg,
            sig = null;

      var promise = Promise.resolve();
      promise = promise.then(function() {
        return algorithms.sign(v.alg, key, msg);
      });
      promise = promise.then(function(result) {
        assert.ok(result.mac);
        assert.deepEqual(result.data, msg);
        sig = result.mac;

        return algorithms.verify(v.alg, key, result.data, result.mac);
      });
      promise = promise.then(function(result) {
        assert.ok(result.valid);
        assert.deepEqual(result.data, msg);
        assert.deepEqual(result.mac, sig);
      });
      return promise;
    });
  });
});
