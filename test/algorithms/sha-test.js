/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/sha", function() {
  var vectors = [
    // SHA-1
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 80-bit message",
      data: "9777cf90dd7c7e863506",
      digest: "05c915b5ed4e4c4afffc202961f3174371e90b5c"
    },
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 160-bit message",
      data: "63a3cc83fd1ec1b6680e9974a0514e1a9ecebb6a",
      digest: "8bb8c0d815a9c68a1d2910f39d942603d807fbcc"
    },
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 256-bit message",
      data: "0321794b739418c24e7c2e565274791c4be749752ad234ed56cb0a6347430c6b",
      digest: "b89962c94d60f6a332fd60f6f07d4f032a586b76"
    },
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 384-bit message",
      data: "57e89659d878f360af6de45a9a5e372ef40c384988e82640a3d5e4b76d2ef181780b9a099ac06ef0f8a7f3f764209720",
      digest: "f652f3b1549f16710c7402895911e2b86a9b2aee"
    },
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 512-bit message",
      data: "45927e32ddf801caf35e18e7b5078b7f5435278212ec6bb99df884f49b327c6486feae46ba187dc1cc9145121e1492e6b06e9007394dc33b7748f86ac3207cfe",
      digest: "a70cfbfe7563dd0e665c7c6715a96a8d756950c0"
    },
    {
      alg: "SHA-1",
      desc: "NIST CAVS SHA-1 2096-bit message",
      data: "6cb70d19c096200f9249d2dbc04299b0085eb068257560be3a307dbd741a3378ebfa03fcca610883b07f7fea563a866571822472dade8a0bec4b98202d47a344312976a7bcb3964427eacb5b0525db22066599b81be41e5adaf157d925fac04b06eb6e01deb753babf33be16162b214e8db017212fafa512cdc8c0d0a15c10f632e8f4f47792c64d3f026004d173df50cf0aa7976066a79a8d78deeeec951dab7cc90f68d16f786671feba0b7d269d92941c4f02f432aa5ce2aab6194dcc6fd3ae36c8433274ef6b1bd0d314636be47ba38d1948343a38bf9406523a0b2a8cd78ed6266ee3c9b5c60620b308cc6b3a73c6060d5268a7d82b6a33b93a6fd6fe1de55231d12c97",
      digest: "4a75a406f4de5f9e1132069d66717fc424376388"
    },
    // SHA-256
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 80-bit message",
      data: "74cb9381d89f5aa73368",
      digest: "73d6fad1caaa75b43b21733561fd3958bdc555194a037c2addec19dc2d7a52bd"
    },
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 160-bit message",
      data: "c1ef39cee58e78f6fcdc12e058b7f902acd1a93b",
      digest: "6dd52b0d8b48cc8146cebd0216fbf5f6ef7eeafc0ff2ff9d1422d6345555a142"
    },
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 256-bit message",
      data: "09fc1accc230a205e4a208e64a8f204291f581a12756392da4b8c0cf5ef02b95",
      digest: "4f44c1c7fbebb6f9601829f3897bfd650c56fa07844be76489076356ac1886a4"
    },
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 384-bit message",
      data: "4eef5107459bddf8f24fc7656fd4896da8711db50400c0164847f692b886ce8d7f4d67395090b3534efd7b0d298da34b",
      digest: "7c5d14ed83dab875ac25ce7feed6ef837d58e79dc601fb3c1fca48d4464e8b83"
    },
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 512-bit message",
      data: "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
      digest: "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa"
    },
    {
      alg: "SHA-256",
      desc: "NIST CAVS SHA-256 2096-bit message",
      data: "6b918fb1a5ad1f9c5e5dbdf10a93a9c8f6bca89f37e79c9fe12a57227941b173ac79d8d440cde8c64c4ebc84a4c803d198a296f3de060900cc427f58ca6ec373084f95dd6c7c427ecfbf781f68be572a88dbcbb188581ab200bfb99a3a816407e7dd6dd21003554d4f7a99c93ebfce5c302ff0e11f26f83fe669acefb0c1bbb8b1e909bd14aa48ba3445c88b0e1190eef765ad898ab8ca2fe507015f1578f10dce3c11a55fb9434ee6e9ad6cc0fdc4684447a9b3b156b908646360f24fec2d8fa69e2c93db78708fcd2eef743dcb9353819b8d667c48ed54cd436fb1476598c4a1d7028e6f2ff50751db36ab6bc32435152a00abd3d58d9a8770d9a3e52d5a3628ae3c9e0325",
      digest: "46500b6ae1ab40bde097ef168b0f3199049b55545a1588792d39d594f493dca7"
    }
  ];

  vectors.forEach(function(v) {
    var runner = function() {
      var data = Buffer.from(v.data, "hex"),
          expected = Buffer.from(v.digest, "hex");

      var promise = algorithms.digest(v.alg, data);
      promise = promise.then(function(result) {
        assert.deepEqual(result, expected);
      });

      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") digest", runner);
  });
});
