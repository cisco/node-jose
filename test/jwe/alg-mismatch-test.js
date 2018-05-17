"use strict";

var chai = require("chai"),
    merge = require("../../lib/util/merge.js");

var JWE = require("../../lib/jwe"),
    JWK = require("../../lib/jwk");

var assert = chai.assert;

describe("jwe/alg-mismatch", function () {
  var a256kw = {
    key: {
      "kty": "oct",
      "kid": "ZMPuzBFdkJTtOxRFoCZcOot3UeaOLiyrUJblGy4PZm0",
      "alg": "A256KW",
      "k": "XZtS3MuR387VRdNHbMDubwLf3uS2QIWFf2f4xnX6aak"
    }
  };
  var a128gcm = {
    key: {
      "kty": "oct",
      "kid": "OJe4kYHZLYSA1yA4HOD57Jk70BXdF3g4Nx-j09zBDF8",
      "alg": "A128GCM",
      "k": "htqVDWv1ke9tGz0Hwqjy0g"
    }
  };
  var rsa_oaep = {
    key: {
      "kty": "RSA",
      "kid": "w3WoHBaDi6JHTyVV4ueFsMUeaGzjZzNmpITzJkKjuiU",
      "alg": "RSA-OAEP",
      "e": "AQAB",
      "n": "muye3G-8larVUwnjsJgTCaN_vWnFcOHQnLJTqFDSNxSiQdTfMLBBtszK1wNVCZmjxqJ17H7T_uTaOz8aJV7eENphfJulE5Iy8kdo23t782y9PXzcqH1OSiYY9SEPtWin7XfnPrOWwCZs5TulpRObH_wk8PA9_L7EZqqqMkEDwvOd34TOC04QrztbQjhdEpObTNad0r5kYh7OFsDJtbndoBiSAYGlL4chhuRWePl7IS0pVTMtJ3wDYwMCVaFfuw_MRRWusRZ3v8AlLsOpq8VdsBAkdsYxkTBQfcTWDBRLGknUSkbEkKvEs5IwiXzMWqDk7U-0_L9X8CwRV50trBM_1w",
      "d": "B9r1lyHHQyN9W4-Fzv92_6cdpAIH89hPVpKoMUGf1xEhxQrBIlvdiSJLKqnNlwYGSt0T86DeqO77rcNeVQTBZ8Na7BGMRjjEgopiY7aYK1iZI9P_8D8iSBo0a8F4ZW9gDGdm_0Pl4epQ3TKwDHW5CN8lFF5qFjWqCbafmJq5URoq9APRvSSAIpVMw321bSumAOLZ8R1CFqcdtD45TNahes1QlHnEnFuFQIS-kbO_SCy9S8bAllITn8j0M3qxEJHSgSlLHvbZ5TQZto4BUeK6usR85-3nE6bzvXs3nhkm75E-I8r43-UV4W8n3iZKDD-vSEhrSUY51M7D8haypuTM4Q",
      "p": "zLlrkNnMmpavTnJE-n_KGFeF_FA98C4xVnWxrdGNiGZpJV9DAnju1NI2YYZBzZdVWFO8ty20Pbnz2luerpfZEH0FA4uh4orQSv-hAJ2CkO-IHevOvJLnf3jIZSy4s6wuqqrK1HicHyU5SBrpUBmfCejufjnOou6qYtNWfr1LZ3E",
      "q": "wbobkbU5QSnsoUg_vKQdeHCWmGv9tBMrnDHlxjgmm4dHeDSrLTgqApdnsM-3rdpFGSa-7SYuPO1ZHU_XC8rILVaGhCUShfLqPCCFDHG22ZRLWBhFRAfpfT6xAyUYfPNK30ccqp1-1L2ldhUy8MWwTrtetG93v3sHIccsWyVdx8c",
      "dp": "zJSiZE7yAq2AJCFWwwj-mNKlxx0cuC5BCYh1dSCKkfrdKgaHPSpCaJRk2ZJDocKP-8M6O8dFbcWsZNHXwdtmg-6bGw7nSC61tay8ZJQCTPnBCT2DC7i19BFsGIbXUF1JCS3BoQ-h3BHjqyWRb4UbA9kssyDrWLCtvjI5Jk_d0VE",
      "dq": "P2KoUJVuBU81WFPuXseHyPd1nqt-2COJmlKNLr0CjNLHZKI--82rmSt2xtg_7gdDooYV5Dwg1tiF1txfrUENHCB6ZNRIakFfuIqfXcH7JNeri0htqWO5VrxjaHcDuyZTchivXXeonuzqLWekQjk8hZYy13C9So5zd-7WKYBhXdM",
      "qi": "bmK6i31vxlOYVpWB88XHmg6c-eGywybYF8FxXrp1McyYfx4aJt-oL5OQSHprqe3-F2y-JPG82y2XVh7oUDl-vzKY-izGEUAkkz5sZZEIYDsDjkPRjwZfQ79dsTe4T9mZ3nFH5aq_wDFMZsNlOdrRaf2FZjPcWXYN265RRhJWMYI"
    }
  };

  var hs256 = {
    key: {
      "kty": "oct",
      "kid": "ZMPuzBFdkJTtOxRFoCZcOot3UeaOLiyrUJblGy4PZm0",
      "alg": "HS256",
      "k": "XZtS3MuR387VRdNHbMDubwLf3uS2QIWFf2f4xnX6aak"
    }
  };
  var rs256 = {
    key: {
      "kty": "RSA",
      "kid": "w3WoHBaDi6JHTyVV4ueFsMUeaGzjZzNmpITzJkKjuiU",
      "alg": "RS256",
      "e": "AQAB",
      "n": "muye3G-8larVUwnjsJgTCaN_vWnFcOHQnLJTqFDSNxSiQdTfMLBBtszK1wNVCZmjxqJ17H7T_uTaOz8aJV7eENphfJulE5Iy8kdo23t782y9PXzcqH1OSiYY9SEPtWin7XfnPrOWwCZs5TulpRObH_wk8PA9_L7EZqqqMkEDwvOd34TOC04QrztbQjhdEpObTNad0r5kYh7OFsDJtbndoBiSAYGlL4chhuRWePl7IS0pVTMtJ3wDYwMCVaFfuw_MRRWusRZ3v8AlLsOpq8VdsBAkdsYxkTBQfcTWDBRLGknUSkbEkKvEs5IwiXzMWqDk7U-0_L9X8CwRV50trBM_1w",
      "d": "B9r1lyHHQyN9W4-Fzv92_6cdpAIH89hPVpKoMUGf1xEhxQrBIlvdiSJLKqnNlwYGSt0T86DeqO77rcNeVQTBZ8Na7BGMRjjEgopiY7aYK1iZI9P_8D8iSBo0a8F4ZW9gDGdm_0Pl4epQ3TKwDHW5CN8lFF5qFjWqCbafmJq5URoq9APRvSSAIpVMw321bSumAOLZ8R1CFqcdtD45TNahes1QlHnEnFuFQIS-kbO_SCy9S8bAllITn8j0M3qxEJHSgSlLHvbZ5TQZto4BUeK6usR85-3nE6bzvXs3nhkm75E-I8r43-UV4W8n3iZKDD-vSEhrSUY51M7D8haypuTM4Q",
      "p": "zLlrkNnMmpavTnJE-n_KGFeF_FA98C4xVnWxrdGNiGZpJV9DAnju1NI2YYZBzZdVWFO8ty20Pbnz2luerpfZEH0FA4uh4orQSv-hAJ2CkO-IHevOvJLnf3jIZSy4s6wuqqrK1HicHyU5SBrpUBmfCejufjnOou6qYtNWfr1LZ3E",
      "q": "wbobkbU5QSnsoUg_vKQdeHCWmGv9tBMrnDHlxjgmm4dHeDSrLTgqApdnsM-3rdpFGSa-7SYuPO1ZHU_XC8rILVaGhCUShfLqPCCFDHG22ZRLWBhFRAfpfT6xAyUYfPNK30ccqp1-1L2ldhUy8MWwTrtetG93v3sHIccsWyVdx8c",
      "dp": "zJSiZE7yAq2AJCFWwwj-mNKlxx0cuC5BCYh1dSCKkfrdKgaHPSpCaJRk2ZJDocKP-8M6O8dFbcWsZNHXwdtmg-6bGw7nSC61tay8ZJQCTPnBCT2DC7i19BFsGIbXUF1JCS3BoQ-h3BHjqyWRb4UbA9kssyDrWLCtvjI5Jk_d0VE",
      "dq": "P2KoUJVuBU81WFPuXseHyPd1nqt-2COJmlKNLr0CjNLHZKI--82rmSt2xtg_7gdDooYV5Dwg1tiF1txfrUENHCB6ZNRIakFfuIqfXcH7JNeri0htqWO5VrxjaHcDuyZTchivXXeonuzqLWekQjk8hZYy13C9So5zd-7WKYBhXdM",
      "qi": "bmK6i31vxlOYVpWB88XHmg6c-eGywybYF8FxXrp1McyYfx4aJt-oL5OQSHprqe3-F2y-JPG82y2XVh7oUDl-vzKY-izGEUAkkz5sZZEIYDsDjkPRjwZfQ79dsTe4T9mZ3nFH5aq_wDFMZsNlOdrRaf2FZjPcWXYN265RRhJWMYI"
    }
  };

  var plaintext = "this is the secret";

  function encryptAllowed(vector, opts) {
    opts = merge({
      format: "compact"
    }, opts || {});

    var p;
    p = JWE.createEncrypt(opts, vector.key).final(plaintext, "utf8");
    p = p.then(function(result) {
      assert.ok(result);
    });
    return p;
  }
  function encryptDisallowed(vector, opts) {
    opts = merge({
      format: "compact"
    }, opts);

    var p;
    p = JWE.createEncrypt(opts, vector.key).final(plaintext, "utf8");
    p = p.then(function () {
      assert.ok(false, "unexpected success");
    }, function (err) {
      assert.ok(err.message);
    });
    return p;
  }

  before(function () {
    var pending = [a128gcm, a256kw, rsa_oaep, hs256, rs256].map(function (v) {
      var p = JWK.asKey(v.key);
      p = p.then(function (jwk) {
        v.key = jwk;
      });
      return p;
    });
    return Promise.all(pending);
  });

  it("disallows on explicit key management algorithm mismatch", function () {
    var opts = {
      fields: {
        alg: "dir"
      }
    };

    var pending = [
      encryptAllowed(a128gcm, opts),
      encryptDisallowed(a256kw, opts),
      encryptDisallowed(rsa_oaep, opts),
      encryptDisallowed(rs256, opts),
      encryptDisallowed(hs256, opts)
    ];
    return Promise.all(pending);
  });
  it("disallows on implicit key-specified mismatch", function () {
    var opts = {
      fields: {
        alg: "RSA-OAEP"
      }
    };

    var pending = [
      encryptDisallowed(a128gcm, opts),
      encryptDisallowed(a256kw, opts),
      encryptAllowed(rsa_oaep, opts),
      encryptDisallowed(rs256, opts),
      encryptDisallowed(hs256, opts)
    ];
    return Promise.all(pending);
  });
  it("disallows on implicit key usage mismatch", function () {
    var pending = [
      encryptAllowed(a128gcm),
      encryptAllowed(a256kw),
      encryptAllowed(rsa_oaep),
      encryptDisallowed(rs256),
      encryptDisallowed(hs256)
    ];
    return Promise.all(pending);
  });
});
