/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/"),
    util = require("../../lib/util");

describe("algorithms/aes-gcm", function() {
  function algSize(alg) {
    return parseInt(/A(\d+)GCM/g.exec(alg)[1]) / 8;
  }
  var fails = [
      "A128GCM",
      "A256GCM"
  ];
  fails.forEach(function(alg, pos) {
    var keyFailer = function(mode) {
      var runner = function() {
        var size = algSize(alg);
        var key,
            iv = Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
            tag = Buffer.from("ffeeddccbbaa99887766554433221100", "hex"),
            plaintext = Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex");

        var promise = Promise.resolve();

        promise = promise.then(function() {
          // a bit too small
          key = Buffer.alloc(size - 1);
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid key size");
        });

        promise = promise.then(function() {
          // a bit too big
          key = Buffer.alloc(size + 1);
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid key size");
        });

        promise = promise.then(function() {
          // just right --- for another algorithm
          var size = algSize(fails[(pos + 1) % fails.length]);
          key = Buffer.alloc(size);
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid key size");
        });

        return promise;
      };

      it("checks for invalid keysize on " + mode + " " + alg, runner);
    };
    var ivFailer = function(mode) {
      var runner = function() {
        var size = algSize(alg);
        var key = Buffer.alloc(size),
            iv,
            tag = Buffer.from("ffeeddccbbaa99887766554433221100", "hex"),
            plaintext = Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex");

        var promise = Promise.resolve();

        promise = promise.then(function() {
          // a bit too small
          iv = Buffer.alloc(12 - 1);
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid iv");
        });

        promise = promise.then(function() {
          // a bit too big
          iv = Buffer.alloc(12 + 1);
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid iv");
        });

        promise = promise.then(function() {
          // outright missing
          iv = undefined;
          return algorithms[mode](alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid iv");
        });

        return promise;
      };

      it("checks for invalid iv on " + mode + " " + alg, runner);
    };
    var tagFailer = function() {
      var runner = function() {
        var size = algSize(alg);
        var key = Buffer.alloc(size),
            iv = Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
            tag,
            plaintext = Buffer.from("bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc", "hex");

        var promise = Promise.resolve();

        promise = promise.then(function() {
          // a bit too small
          tag = Buffer.alloc(16 - 1);
          return algorithms.decrypt(alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid tag length");
        });

        promise = promise.then(function() {
          // a bit too big
          tag = Buffer.alloc(16 + 1);
          return algorithms.decrypt(alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid tag length");
        });

        promise = promise.then(function() {
          // outright missing
          tag = undefined;
          return algorithms.decrypt(alg, key, plaintext, { iv: iv, mac: tag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.equal(err.message, "invalid tag length");
        });

        return promise;
      };

      it("checks for invalid tag on decrypt " + alg, runner);
    };
    var decryptFailer = function(){
      var runner = function() {
        var size = algSize(alg);
        var key = Buffer.alloc(size),
            iv = Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
            tag,
            plaintext = Buffer.from("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "hex"),
            ciphertext;

        var promise = Promise.resolve();
        promise = promise.then(function() {
          return algorithms.encrypt(alg, key, plaintext, { iv: iv });
        });
        promise = promise.then(function(result) {
          ciphertext = result.data;
          tag = result.tag;

          // corrupted tag
          var badTag = Buffer.alloc(tag.length);
          tag.copy(badTag);
          for (var idx = 0; idx < badTag.length; idx++) {
            badTag[idx] = badTag[idx] ^ 0xa5;
          }
          return algorithms.decrypt(alg, key, ciphertext, { iv: iv, mac: badTag });
        });
        promise = promise.then(function() {
          assert.ok(false, "expected error not thrown");
        }, function(err) {
          assert.ok(!!err);
        });

        return promise;
      };

      it("checks for failed decryption on " + alg, runner);
    };

    keyFailer("encrypt");
    keyFailer("decrypt");
    ivFailer("encrypt");
    ivFailer("decrypt");
    tagFailer();
    decryptFailer();
  });

  var vectors = [
    // 128-bit key, 0-bit AAD
    {
      alg: "A128GCM",
      desc: "NIST-CAVP [128-bit key, 0-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "e98b72a9881a84ca6b76e0f43e68647a",
      iv: "8b23299fde174053f3d652ba",
      plaintext: "28286a321293253c3e0aa2704a278032",
      ciphertext: "5a3c1cf1985dbb8bed818036fdd5ab42",
      aad: "",
      tag: "23c7ab0f952b7091cd324835043b5eb5"
    },
    // 128-bit key, 128-bit AAD
    {
      alg: "A128GCM",
      desc: "NIST-CAVP [128-bit key, 128-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "816e39070410cf2184904da03ea5075a",
      iv: "32c367a3362613b27fc3e67e",
      plaintext: "ecafe96c67a1646744f1c891f5e69427",
      ciphertext: "552ebe012e7bcf90fcef712f8344e8f1",
      aad: "f2a30728ed874ee02983c294435d3c16",
      tag: "ecaae9fc68276a45ab0ca3cb9dd9539f"
    },
    {
      wrap: true,
      alg: "A128GCMKW",
      desc: "NIST-CAVP [128-bit key, 0-bit AAD, 96-bit IV, 128-bit TAG] for Key Wrapping",
      key: "e98b72a9881a84ca6b76e0f43e68647a",
      iv: "8b23299fde174053f3d652ba",
      plaintext: "28286a321293253c3e0aa2704a278032",
      ciphertext: "5a3c1cf1985dbb8bed818036fdd5ab42",
      aad: "",
      tag: "23c7ab0f952b7091cd324835043b5eb5"
    },

    /*! NOT SUPPORTED ON CHROME
    // 192-bit key, 0-bit AAD
    {
      alg: "A192GCM",
      desc: "NIST-CAVP [192-bit key, 0-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "7a7c5b6a8a9ab5acae34a9f6e41f19a971f9c330023c0f0c",
      iv: "aa4c38bf587f94f99fee77d5",
      plaintext: "99ae6f479b3004354ff18cd86c0b6efb",
      ciphertext: "132ae95bd359c44aaefa6348632cafbd",
      aad: "",
      tag: "19d7c7d5809ad6648110f22f272e7d72"
    },
    // 192-bit key, 128-bit AAD
    {
      alg: "A192GCM",
      desc: "NIST-CAVP [192-bit key, 128-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "0c44d6c928ee112ce665fe547ebd387298a954b462f695d8",
      iv: "18b8f320fef4ae8ccbe8f952",
      plaintext: "96ad07f9b628b652cf86cb7317886f51",
      ciphertext: "a664078133405eb9094d36f7e070191f",
      aad: "7341d43f98cf388221180941970376e8",
      tag: "e8f9c317847ce3f3c23994a402f06581"
    },
    //*/

    // 256-bit key, 0-bit AAD
    {
      alg: "A256GCM",
      desc: "NIST-CAVP [256-bit key, 0-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8",
      iv: "473360e0ad24889959858995",
      plaintext: "7789b41cb3ee548814ca0b388c10b343",
      ciphertext: "d2c78110ac7e8f107c0df0570bd7c90c",
      aad: "",
      tag: "c26a379b6d98ef2852ead8ce83a833a7"
    },
    // 256-bit key, 128-bit AAD
    {
      alg: "A256GCM",
      desc: "NIST-CAVP [256-bit key, 128-bit AAD, 96-bit IV, 128-bit TAG]",
      key: "54e352ea1d84bfe64a1011096111fbe7668ad2203d902a01458c3bbd85bfce14",
      iv: "df7c3bca00396d0c018495d9",
      plaintext: "85fc3dfad9b5a8d3258e4fc44571bd3b",
      ciphertext: "426e0efc693b7be1f3018db7ddbb7e4d",
      aad: "7e968d71b50c1f11fd001f3fef49d045",
      tag: "ee8257795be6a1164d7e1d2d6cac77a7"
    },
    {
      wrap: true,
      alg: "A256GCMKW",
      desc: "NIST-CAVP [256-bit key, 0-bit AAD, 96-bit IV, 128-bit TAG] for Key Wrapping",
      key: "4c8ebfe1444ec1b2d503c6986659af2c94fafe945f72c1e8486a5acfedb8a0f8",
      iv: "473360e0ad24889959858995",
      plaintext: "7789b41cb3ee548814ca0b388c10b343",
      ciphertext: "d2c78110ac7e8f107c0df0570bd7c90c",
      aad: "",
      tag: "c26a379b6d98ef2852ead8ce83a833a7"
    }
  ];
  vectors.forEach(function(v) {
    var encrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex"),
          mac = Buffer.from(v.tag, "hex"),
          props = {
            iv: Buffer.from(v.iv, "hex"),
            aad: Buffer.from(v.aad, "hex")
          };

      var promise = algorithms.encrypt(v.alg, key, pdata, props);
      promise = promise.then(function(result) {
        assert.deepEqual(result.data, cdata);

        if (v.wrap) {
          var header = result.header;
          assert.deepEqual(header.iv, util.base64url.encode(props.iv));
          assert.deepEqual(header.tag, util.base64url.encode(mac));
        } else {
          assert.deepEqual(result.tag, mac);
        }
      });
      return promise;
    };
    var decrunner = function() {
      var key = Buffer.from(v.key, "hex"),
          pdata = Buffer.from(v.plaintext, "hex"),
          cdata = Buffer.from(v.ciphertext, "hex"),
          props = {
            iv: Buffer.from(v.iv, "hex"),
            aad: Buffer.from(v.aad, "hex"),
            tag: Buffer.from(v.tag, "hex")
          };

      var promise = algorithms.decrypt(v.alg, key, cdata, props);
      promise = promise.then(function(result) {
        assert.deepEqual(result, pdata);
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") encryption", encrunner);
    it("performs " + v.alg + " (" + v.desc + ") decryption", decrunner);
  });

  it("performs consistently with large data", function() {
    var key = Buffer.from("00000000000000000000000000000000", "hex"),
        iv = Buffer.from("a5a5a5a5a5a5a5a5a5a5a5a5", "hex"),
        plaintext = Buffer.alloc(1024 * 1024 + 1);

    for (var idx = 0; idx < plaintext.length; idx++) {
      plaintext[idx] = idx % 256;
    }
    var promise = Promise.resolve(plaintext);
    promise = promise.then(function(pdata) {
      var props = {
        iv: iv
      };
      return algorithms.encrypt("A128GCM", key, pdata, props);
    });
    promise = promise.then(function(result) {
      var cdata = result.data,
          tag = result.tag;

      var props = {
        iv: iv,
        tag: tag
      };
      return algorithms.decrypt("A128GCM", key, cdata, props);
    });
    promise = promise.then(function(result) {
      assert.deepEqual(result, plaintext);
    });
    return promise;
  });
});
