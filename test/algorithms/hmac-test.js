/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/");

describe("algorithms/hmac", function() {
  var vectors = [
    /*
    // ### NOTE: NOT PART OF JOSE!!!
    // SHA-1
    {
      alg: "SHA-1",
      desc: "RFC2202 test #1",
      key: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
      msg: "4869205468657265",  // "Hi There"
      mac: "b617318655057264e28bc0b6fb378c8ef146be00",
    },
    {
      alg: "SHA-1",
      desc: "RFC2202 test #3",
      key: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      msg: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      mac: "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    },
    {
      alg: "SHA-1",
      desc: "NIST-CAVP v11 test #105",
      key: "895868f19695c1f5a26d8ae339c567e5ab43b0fcc8056050e9922ec53010f9ce",
      msg: "883e6ca2b19ef54640bb8333f85a9380e17211f6ee3d1dc7dc8f0e7c5d67b73076c3eafc26b93bb248c406ceba5cb4a9bfc939f0a238e1559d0f4d84f87eb85975568050ec1fe13d3365033d405237ec92827dd8cd124b36a4fa89d4fb9de04f4d9f34864cf76f4ec8458168d265a5b02144e596b5f2e0d2b9f9cb54aeeeb67a",
      mac: "374c88f4480f5e8aaa9f448b777557c50065e9ac",
    },
    //*/

    // SHA-256
    {
      alg: "HS256",
      desc: "NIST-CAVP v11 test #30",
      key: "9779d9120642797f1747025d5b22b7ac607cab08e1758f2f3a46c8be1e25c53b8c6a8f58ffefa176",
      msg: "b1689c2591eaf3c9e66070f8a77954ffb81749f1b00346f9dfe0b2ee905dcc288baf4a92de3f4001dd9f44c468c3d07d6c6ee82faceafc97c2fc0fc0601719d2dcd0aa2aec92d1b0ae933c65eb06a03c9c935c2bad0459810241347ab87e9f11adb30415424c6c7f5f22a003b8ab8de54f6ded0e3ab9245fa79568451dfa258e",
      mac: "769f00d3e6a6cc1fb426a14a4f76c6462e6149726e0dee0ec0cf97a16605ac8b"
    },

    // SHA-384
    {
      alg: "HS384",
      desc: "NIST-CAVP v11 test #45",
      key: "5eab0dfa27311260d7bddcf77112b23d8b42eb7a5d72a5a318e1ba7e7927f0079dbb701317b87a3340e156dbcee28ec3a8d9",
      msg: "f41380123ccbec4c527b425652641191e90a17d45e2f6206cf01b5edbe932d41cc8a2405c3195617da2f420535eed422ac6040d9cd65314224f023f3ba730d19db9844c71c329c8d9d73d04d8c5f244aea80488292dc803e772402e72d2e9f1baba5a6004f0006d822b0b2d65e9e4a302dd4f776b47a972250051a701fab2b70",
      mac: "7cf5a06156ad3de5405a5d261de90275f9bb36de45667f84d08fbcb308ca8f53a419b07deab3b5f8ea231c5b036f8875"
    },

    // SHA-512
    {
      alg: "HS512",
      desc: "NIST-CAVP v11 test #60",
      key: "57c2eb677b5093b9e829ea4babb50bde55d0ad59fec34a618973802b2ad9b78e26b2045dda784df3ff90ae0f2cc51ce39cf54867320ac6f3ba2c6f0d72360480c96614ae66581f266c35fb79fd28774afd113fa5187eff9206d7cbe90dd8bf67c844e202",
      msg: "2423dff48b312be864cb3490641f793d2b9fb68a7763b8e298c86f42245e4540eb01ae4d2d4500370b1886f23ca2cf9701704cad5bd21ba87b811daf7a854ea24a56565ced425b35e40e1acbebe03603e35dcf4a100e57218408a1d8dbcc3b99296cfea931efe3ebd8f719a6d9a15487b9ad67eafedf15559ca42445b0f9b42e",
      mac: "33c511e9bc2307c62758df61125a980ee64cefebd90931cb91c13742d4714c06de4003faf3c41c06aefc638ad47b21906e6b104816b72de6269e045a1f4429d4"
    }
  ];

  vectors.forEach(function(v) {
    var signrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          msg = Buffer.from(v.msg, "hex"),
          mac = Buffer.from(v.mac, "hex");

      var promise = algorithms.sign(v.alg, key, msg);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("binary"), msg.toString("binary"));
        assert.equal(result.mac.toString("binary"), mac.toString("binary"));
      });

      return promise;
    };
    var vfyrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          msg = Buffer.from(v.msg, "hex"),
          mac = Buffer.from(v.mac, "hex");

      var promise = algorithms.verify(v.alg, key, msg, mac);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("binary"), msg.toString("binary"));
        assert.equal(result.mac.toString("binary"), mac.toString("binary"));
        assert.equal(result.valid, true);
      });

      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ")" + " generation", signrunner);
    it("performs " + v.alg + " (" + v.desc + ")" + " verification", vfyrunner);
  });
});
