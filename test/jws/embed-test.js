/*!
 *
 * Copyright (c) 2016 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");

var JWS = require("../../lib/jws");
var JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jws/embedded", function() {
  var key = {
    "kty": "RSA",
    "kid": "2994e519-8d46-4b91-a33b-9979c8afa593",
    "e": "AQAB",
    "n": "lgCWZN9AU-GJJDO7uIaZP3X0LmhqjVvj-4KqRGh-BvbkLtLuJjrZ-TyitFRUw1jhE25vuhAi-tphyhR_dqHOd6f-X8DwCkM-esD8JDa-I1lYA1h9c-MUlsEGbVlbxwTbB1Nus47vd6lEx_03r5WQtJW9LyAgHiQBKoDDITGHYUOTd6tTRre00G4SCfvA2oAc2xl5RE-5S63yFGp48TKdudbLl6M3M3JHiUVrBY2qQKovJKm8NXPIJ5kaBo7lQrzN7o4nw89FvoLZZ22dK9sHP8Do8oHk7mF40Q5m4dVDWnvqxczldqtYNyEhr27ERTlaSeckUDTvq_3Gklq7RgPJnQ",
    "d": "EoVoDHR0YOcMI-gvWY1lBqztxX0nCuU5tShhFalBRmLdsdphhV7m4xtVi6aOAMDMqbWNHhA4AXlNccIuKtu3vpaDlhcgjGPZJxcFCwOnXn39nAwlEVYMiMC0pnPOHTjAQptOo-UWNFQ2JetiIM_62hFTFqqEzLPtYO4dKdAPwzZ_wyDMiT78RKMfXriExxusZ7KJVU-yJs6yKvO6XnaNRK8CT_JL5DQDBA2iaah_P3P3AWAr20QPXrY-jL3j0kSb9OBM_Z89-mUhoseBgiHYkux0ZdNS6Y5du3CquDIS041tfVWZYc7awM2SlHwEIGLXftvZs7L0J-ZxW-VZUAzPEQ",
    "p": "51_0X26mpJqTev8J0nTqnOz9v9eaKStx8dXuQz5ygTattcICwNiU1swGlU5R4YHmmq955WsK8rcQbq0H6Yx1eoLVzU8uBuzWj9z-M4qcIEKUeQHHeIbekV43UZs8KkD9yyaQTm_zAMHeeM_RtM4BySym4PPoSYRGhqMBKJXljXc",
    "q": "pfeN9m_PFeq0oFlHni3j2KhqZwyAry093kcoJGs5OSK5gS1t-eHkLAX89Bve_4pmPRl3zdLkAUNOazk-lPPkbI5in51esgyrx7VsnpmsZ4i4Smk1JgSDTmYcG7PH81Z6rIFmpLY66wUhpqg7ONVFvl0M3kP7aXMuSdumWPB2Vos",
    "dp": "I4X58QT-FNuetQ2fJm7I7pr8Qo4JnzSKZATidfSKhAgvF27YGV-nSms8v4Os0qCtFSbH4k9S-PzeSv_J7TOhfdPEm6cCfBG0x5W4eZVYbyOJxCJfy8N5PHxopeDdlecwkBY1pbVOa9lYHNhbbBUM9SQj4vnPuinS4iz4qpCJE_U",
    "dq": "F0nBVc8ik8S3S7i7X-q4ifI32_XZKLuEbug1LccN5IKG3SVuxR15UuQUNnyiseDNr80fDnaFH9g97LW_nk8KwmDIXfVLEFjO0dsXPrn5gx2gHnDc0FTZx-p0Dz8O04pS9FnD-WDIq6mwqx34EWV7v9Z2s8l-QbGz0RFNKjWzpTk",
    "qi": "uGslfmgxbrmeF8k4a2-sI4oMd0igZ_2kyAZXYsCXnYd6aO5iCEG9hQE9gOJ29qXReiec0F0ZZ873ROaFWZDaANbek6J7-5NJavTBEdyvT840m1siHIxX7j28-BVOcnI050cEUm4iM1y027Cll4Q4-qp54SmcO3hLhuXL3cT_apQ"
  };
  var cert = [
    "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"
  ];
  var payload = Buffer.from("There and back again – A Hobbit's Tale, by Bilbo Baggins", "utf8");

  before(function() {
    return JWK.asKey(key).
           then(function(jwk) {
             key = jwk;
           });
  })

  describe("jwk", function() {
    var signature;
    it("creates a JWS with an embedded 'jwk'", function() {
      var opts = {
            format: "flattened",
            protect: false
          },
          jws,
          p;

      jws = JWS.createSign(opts, {
        key: key,
        reference: "jwk"
      });
      jws.update(payload);
      p = jws.final();
      p = p.then(function(result) {
        var header = {
          alg: "RS256",
          jwk: key.toJSON()
        };
        assert.deepEqual(result.header, header);
        signature = result;
      });
      return p;
    });
    it("by default fails verify if 'allowEmbeddedKey' not true", function() {
      var p;
      var vfy = JWS.createVerify(JWK.createKeyStore());
      p = vfy.verify(signature);
      p = p.then(
        function () {
          assert.ok(false, "unexpected success");
        },
        function (err) {
          assert(err instanceof Error);
      });
      return p;
    });
    it("verifies a JWS using an embedded 'jwk'", function() {
      var opts = {
        allowEmbeddedKey: true
      };
      var p;
      var vfy = JWS.createVerify(JWK.createKeyStore());
      p = vfy.verify(signature, opts);
      p = p.then(function(result) {
        assert.deepEqual(result.payload, payload);
      });
      return p;
    });
  });

  //TODO: x5c
  describe("x5c", function() {
    var signature;
    it("creates a JWS with an embedded 'x5c'", function() {
      var opts = {
            format: "flattened",
            protect: false
          },
          jws,
          p;

      jws = JWS.createSign(opts, {
        key: key,
        reference: "x5c",
        header: {
          x5c: cert
        }
      });
      jws.update(payload);
      p = jws.final();
      p = p.then(function(result) {
        var header = {
          alg: "RS256",
          x5c: cert
        };
        assert.deepEqual(result.header, header);
        signature = result;
      });
      return p;
    });
    it("by default fails verify if 'allowEmbeddedKey' not true", function() {
      var p;
      var vfy = JWS.createVerify(JWK.createKeyStore());
      p = vfy.verify(signature);
      p = p.then(
        function () {
          assert.ok(false, "unexpected success");
        },
        function (err) {
          assert(err instanceof Error);
      });
      return p;
    });
    it("verifies a JWS using an embedded 'x5c'", function() {
      var opts = {
        allowEmbeddedKey: true
      };
      var p;
      var vfy = JWS.createVerify(JWK.createKeyStore());
      p = vfy.verify(signature, opts);
      p = p.then(function(result) {
        assert.deepEqual(result.payload, payload);
      });
      return p;
    });
    it("verifies a JWS using an embedded 'x5c' with createVerify configuration", function() {
      var opts = {
        allowEmbeddedKey: true
      };
      var p;
      var vfy = JWS.createVerify(JWK.createKeyStore(), opts);
      p = vfy.verify(signature);
      p = p.then(function(result) {
        assert.deepEqual(result.payload, payload);
      });
      return p;
    });
  });

  describe("invalid", function() {
    var badKey = {
      "kty": "oct",
      "kid": "dNr5z3PMFZKDp7Kh7uAxmpuSiOrm0E3WZDEscsoRXeE",
      "alg": "HS256",
      "k": "UHZVSbwjVqqFCcdQUvrnX7gLXBIfMEkecVeYE7tD7fo"
    };
    before(function() {
      return JWK.asKey(badKey).
             then(function(result) {
               badKey = result;
             });
    });
    it("failed to embed a symmetric key", function() {
      var opts = {
        format: "general",
        protect: false
      };
      var jws = JWS.createSign(opts, {
        key: badKey,
        reference: "jwk"
      });
      jws.update("You shall not pass!", "utf8");

      var p = jws.final();
      p = p.then(function() {
        assert.ok(false, "unexpected fail");
      }, function(err) {
        assert.instanceOf(err, Error);
        assert.equal(err.message, "cannot embed key");
      });
      return p;
    });
  });
});
