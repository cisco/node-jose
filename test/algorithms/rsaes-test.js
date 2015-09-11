/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/"),
    util = require("../../lib/util");

describe("algorithms/rsaes", function() {
  var vectors = [
    // 2048-bit; RSAES-PKCS-V1_5
    {
      alg: "RSA1_5",
      desc: "RSAES-PKCS-V1_5",
      key: {
        "kty": "RSA",
        "n": util.base64url.decode("tHxy-fcpeVkvyncpt0xiMRvmKkpLzvd58AFpjHc4fUAqPgIGB7W4TBwTLWFB86p70ZwWYAcZtlxDS5xIfTFSh5sQp9Fw6DK45Jsjqho4WSkx88vrHtHSgIYepyqN88TjOMZnMpArZe1MaWt8jMLq2zia8V07XZx8j33iIKB_cSUcyNaiFYX9xthxiMJT4fAP8mer0N2GMhQnZcucltV9aHN-aMs0srsFpoiWtGFVmW72wF5EAJ-lMConfiImADGnyO6kuhRSsz39_3u3Q7kpcj757-cmCp4pUKn4vROCt3v-Rj_OHmNG5hONtWUeTg7IxAmZtRX_D3OA7eCjzLrb9w"),
        "e": util.base64url.decode("AQAB"),
        "d": util.base64url.decode("SBOa5vApg-h2CWjlI-pBHFOD60eYVqLF827c89d4m6xQMksklVegreRYVDsO13wxzleDJ_4t6oGV7lAPMs_LoZPvZtVhPZlj9QdvirLF5fVpmW7KCpjIc8Mb4q4_2iW6iCXTeIHSkvXdGgxuxNfiaoGEfvc4if3AUJ14_Iab3lbBrsoGcDOgXQZcv2oZbpt4o4NlsesFymrNnUIJbVyQ73nErfjxZOBjJmS8IIeqHNkWM-1cGnWYc4oMBbeVkHq7ZPwGsDg44g9pP9K_ukFeb9umxXwg_NwknLCn2PoPLGu9MoHolyweYU-EDeKtZlLKoKIAnO3tS-HKVS20TrN0YQ"),
        "p": util.base64url.decode("_pDg8_8vC80BGbZBUXUZSCPwZmKPAwK_XXOZdvyxEgPsMFJB0wEJeDI1vp6cC_gb-nlsQ9QuvrQJK2tSZ42fiwnVcdgImp7s6g3diVS35UwlnfRtaPCQMoyUGY0Ysr-455kgEmgjFX6JSO41ghun2tRv9NHtk4zTPEhMrcAu9-U"),
        "q": util.base64url.decode("tYC8i1xkykvIdTo82BWKYA4LgcoCsISAkf7gRPykOJFhHeM6FHEoYJbLZ7QTW1lhMojgZM6Px_6qyjrDRRQoRz1m8eSFd7v3wq_i94n4sN4MTgDYtj6-VBynYBdF0KXX4z42CzR2rhWXmOKCGCM4KjH9jyTTQq8zAd6BcKpNzqs"),
        "dp": util.base64url.decode("8sfrsuixzrhij0oRu4VJalLUSGFA8WciaRcBysgue_b_wAoDOyDnDhocxcJxIr0qudQp2_q15iy__gfp3FbmTO1BAsU9V3Gwk3xLx1jj1aysx5tA6W9cpskJyeCWKIvO5hpUyxlENJCsj8CXiZGkoYAvkjbQNQN-xiRR9PewE70"),
        "dq": util.base64url.decode("pbvG7q5QbpSil8C0_E83CpzojvwqVoq3aBjHKtdTEUBW4NazGyV0zDYFyE0be8dyxJVN6V7g1atKwtzDn9lXKi38SZb09K9T_pdi9cwrpT0tGTEWsds7Kkz73PeDTZGSP7N33-VpFW8r_XOffXDzgTwin0nuCq82MVe-9GTeJX8"),
        "qi": util.base64url.decode("v9JNqwr4j8nUn3hqFxip2vsn6E0SVvUe29y0LvysXdYjeI3mCAEzZoymycjZ8DPkR9VeKshIMJS92a_Fr4njq98HGjqKJ_NtLgCLglQtiW_NDZvdH930hn80qCSe_6wgP3ZVVAh054MzcxcCoFp1KaOalahf2OW8t9I6eRDF0OQ")
      },
      msg: util.base64url.decode("d50euE-ihMN9KdXhedADBrQTxEqACgd-WYU_YwX5Lln7f4E")
    },
    // 2048-bit; RSAES-OAEP; SHA-1
    {
      alg: "RSA-OAEP",
      desc: "RSA-OAEP using SHA-1 for Hash and MGF1",
      key: {
        "kty": "RSA",
        "n": util.base64url.decode("tHxy-fcpeVkvyncpt0xiMRvmKkpLzvd58AFpjHc4fUAqPgIGB7W4TBwTLWFB86p70ZwWYAcZtlxDS5xIfTFSh5sQp9Fw6DK45Jsjqho4WSkx88vrHtHSgIYepyqN88TjOMZnMpArZe1MaWt8jMLq2zia8V07XZx8j33iIKB_cSUcyNaiFYX9xthxiMJT4fAP8mer0N2GMhQnZcucltV9aHN-aMs0srsFpoiWtGFVmW72wF5EAJ-lMConfiImADGnyO6kuhRSsz39_3u3Q7kpcj757-cmCp4pUKn4vROCt3v-Rj_OHmNG5hONtWUeTg7IxAmZtRX_D3OA7eCjzLrb9w"),
        "e": util.base64url.decode("AQAB"),
        "d": util.base64url.decode("SBOa5vApg-h2CWjlI-pBHFOD60eYVqLF827c89d4m6xQMksklVegreRYVDsO13wxzleDJ_4t6oGV7lAPMs_LoZPvZtVhPZlj9QdvirLF5fVpmW7KCpjIc8Mb4q4_2iW6iCXTeIHSkvXdGgxuxNfiaoGEfvc4if3AUJ14_Iab3lbBrsoGcDOgXQZcv2oZbpt4o4NlsesFymrNnUIJbVyQ73nErfjxZOBjJmS8IIeqHNkWM-1cGnWYc4oMBbeVkHq7ZPwGsDg44g9pP9K_ukFeb9umxXwg_NwknLCn2PoPLGu9MoHolyweYU-EDeKtZlLKoKIAnO3tS-HKVS20TrN0YQ"),
        "p": util.base64url.decode("_pDg8_8vC80BGbZBUXUZSCPwZmKPAwK_XXOZdvyxEgPsMFJB0wEJeDI1vp6cC_gb-nlsQ9QuvrQJK2tSZ42fiwnVcdgImp7s6g3diVS35UwlnfRtaPCQMoyUGY0Ysr-455kgEmgjFX6JSO41ghun2tRv9NHtk4zTPEhMrcAu9-U"),
        "q": util.base64url.decode("tYC8i1xkykvIdTo82BWKYA4LgcoCsISAkf7gRPykOJFhHeM6FHEoYJbLZ7QTW1lhMojgZM6Px_6qyjrDRRQoRz1m8eSFd7v3wq_i94n4sN4MTgDYtj6-VBynYBdF0KXX4z42CzR2rhWXmOKCGCM4KjH9jyTTQq8zAd6BcKpNzqs"),
        "dp": util.base64url.decode("8sfrsuixzrhij0oRu4VJalLUSGFA8WciaRcBysgue_b_wAoDOyDnDhocxcJxIr0qudQp2_q15iy__gfp3FbmTO1BAsU9V3Gwk3xLx1jj1aysx5tA6W9cpskJyeCWKIvO5hpUyxlENJCsj8CXiZGkoYAvkjbQNQN-xiRR9PewE70"),
        "dq": util.base64url.decode("pbvG7q5QbpSil8C0_E83CpzojvwqVoq3aBjHKtdTEUBW4NazGyV0zDYFyE0be8dyxJVN6V7g1atKwtzDn9lXKi38SZb09K9T_pdi9cwrpT0tGTEWsds7Kkz73PeDTZGSP7N33-VpFW8r_XOffXDzgTwin0nuCq82MVe-9GTeJX8"),
        "qi": util.base64url.decode("v9JNqwr4j8nUn3hqFxip2vsn6E0SVvUe29y0LvysXdYjeI3mCAEzZoymycjZ8DPkR9VeKshIMJS92a_Fr4njq98HGjqKJ_NtLgCLglQtiW_NDZvdH930hn80qCSe_6wgP3ZVVAh054MzcxcCoFp1KaOalahf2OW8t9I6eRDF0OQ")
      },
      msg: util.base64url.decode("d50euE-ihMN9KdXhedADBrQTxEqACgd-WYU_YwX5Lln7f4E")
    },
    // 2048-bit; RSAES-OAEP; SHA-256
    {
      alg: "RSA-OAEP-256",
      desc: "RSA-OAEP using SHA-256 for Hash and MGF1",
      key: {
        "kty": "RSA",
        "n": util.base64url.decode("tHxy-fcpeVkvyncpt0xiMRvmKkpLzvd58AFpjHc4fUAqPgIGB7W4TBwTLWFB86p70ZwWYAcZtlxDS5xIfTFSh5sQp9Fw6DK45Jsjqho4WSkx88vrHtHSgIYepyqN88TjOMZnMpArZe1MaWt8jMLq2zia8V07XZx8j33iIKB_cSUcyNaiFYX9xthxiMJT4fAP8mer0N2GMhQnZcucltV9aHN-aMs0srsFpoiWtGFVmW72wF5EAJ-lMConfiImADGnyO6kuhRSsz39_3u3Q7kpcj757-cmCp4pUKn4vROCt3v-Rj_OHmNG5hONtWUeTg7IxAmZtRX_D3OA7eCjzLrb9w"),
        "e": util.base64url.decode("AQAB"),
        "d": util.base64url.decode("SBOa5vApg-h2CWjlI-pBHFOD60eYVqLF827c89d4m6xQMksklVegreRYVDsO13wxzleDJ_4t6oGV7lAPMs_LoZPvZtVhPZlj9QdvirLF5fVpmW7KCpjIc8Mb4q4_2iW6iCXTeIHSkvXdGgxuxNfiaoGEfvc4if3AUJ14_Iab3lbBrsoGcDOgXQZcv2oZbpt4o4NlsesFymrNnUIJbVyQ73nErfjxZOBjJmS8IIeqHNkWM-1cGnWYc4oMBbeVkHq7ZPwGsDg44g9pP9K_ukFeb9umxXwg_NwknLCn2PoPLGu9MoHolyweYU-EDeKtZlLKoKIAnO3tS-HKVS20TrN0YQ"),
        "p": util.base64url.decode("_pDg8_8vC80BGbZBUXUZSCPwZmKPAwK_XXOZdvyxEgPsMFJB0wEJeDI1vp6cC_gb-nlsQ9QuvrQJK2tSZ42fiwnVcdgImp7s6g3diVS35UwlnfRtaPCQMoyUGY0Ysr-455kgEmgjFX6JSO41ghun2tRv9NHtk4zTPEhMrcAu9-U"),
        "q": util.base64url.decode("tYC8i1xkykvIdTo82BWKYA4LgcoCsISAkf7gRPykOJFhHeM6FHEoYJbLZ7QTW1lhMojgZM6Px_6qyjrDRRQoRz1m8eSFd7v3wq_i94n4sN4MTgDYtj6-VBynYBdF0KXX4z42CzR2rhWXmOKCGCM4KjH9jyTTQq8zAd6BcKpNzqs"),
        "dp": util.base64url.decode("8sfrsuixzrhij0oRu4VJalLUSGFA8WciaRcBysgue_b_wAoDOyDnDhocxcJxIr0qudQp2_q15iy__gfp3FbmTO1BAsU9V3Gwk3xLx1jj1aysx5tA6W9cpskJyeCWKIvO5hpUyxlENJCsj8CXiZGkoYAvkjbQNQN-xiRR9PewE70"),
        "dq": util.base64url.decode("pbvG7q5QbpSil8C0_E83CpzojvwqVoq3aBjHKtdTEUBW4NazGyV0zDYFyE0be8dyxJVN6V7g1atKwtzDn9lXKi38SZb09K9T_pdi9cwrpT0tGTEWsds7Kkz73PeDTZGSP7N33-VpFW8r_XOffXDzgTwin0nuCq82MVe-9GTeJX8"),
        "qi": util.base64url.decode("v9JNqwr4j8nUn3hqFxip2vsn6E0SVvUe29y0LvysXdYjeI3mCAEzZoymycjZ8DPkR9VeKshIMJS92a_Fr4njq98HGjqKJ_NtLgCLglQtiW_NDZvdH930hn80qCSe_6wgP3ZVVAh054MzcxcCoFp1KaOalahf2OW8t9I6eRDF0OQ")
      },
      msg: util.base64url.decode("ISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISEhISE")
    }
  ];

  vectors.forEach(function(v) {
    // NOTE: The best we can really do is consistency checks
    it("performs " + v.alg + " (" + v.desc + ") encrypt+decrypt consistency", function() {
        var key = v.key,
            msg = v.msg;

      var promise = Promise.resolve();
      promise = promise.then(function() {
        return algorithms.encrypt(v.alg, key, msg);
      });
      promise = promise.then(function(result) {
        assert.ok(result.data);

        return algorithms.decrypt(v.alg, key, result.data);
      });
      promise = promise.then(function(result) {
        assert.deepEqual(result, v.msg);
      });
      return promise;
    });
  });
});
