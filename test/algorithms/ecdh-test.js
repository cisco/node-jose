/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var omit = require("lodash/omit"),
    chai = require("chai"),
    bowser = require("bowser");
var assert = chai.assert;

var algorithms = require("../../lib/algorithms/"),
    util = require("../../lib/util");

describe("algorithms/ecdh", function() {
  var deriveVectors = [
    // ECDH Raw
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EC-SHA256 #2 [Raw ECDH P-256 to 256-bit secret]",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("7zbcQ6Fdncg6rLODr7kf8LKLi3gG97w9TDLtb015yu8"),
        x: util.base64url.decode("S5n2_0SoNTscyrut1NQGPCpwmWtvHxpZOwqJXkg_s4w"),
        y: util.base64url.decode("SS7aA0CHkIeIJNWRDVG3TndlHgGDpBe1itliHNJf0t0")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("YHgubzHrfUD4iNc1-K0XqtZDtIdviLirkP9Px2sMnFU"),
        y: util.base64url.decode("KNJTFg1mCIkpRtTF3a6OgBpjz272RiUtlfNB3vuAfrE")
      },
      secret: util.base64url.decode("ADuEaC75luRirAT79o0ZoY-3T4ad-H3yTN_PIeIZR4Q"),
      keyLength: 32
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EC-SHA256 #2 [Raw ECDH P-256 to 128-bit secret]",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("7zbcQ6Fdncg6rLODr7kf8LKLi3gG97w9TDLtb015yu8"),
        x: util.base64url.decode("S5n2_0SoNTscyrut1NQGPCpwmWtvHxpZOwqJXkg_s4w"),
        y: util.base64url.decode("SS7aA0CHkIeIJNWRDVG3TndlHgGDpBe1itliHNJf0t0")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("YHgubzHrfUD4iNc1-K0XqtZDtIdviLirkP9Px2sMnFU"),
        y: util.base64url.decode("KNJTFg1mCIkpRtTF3a6OgBpjz272RiUtlfNB3vuAfrE")
      },
      secret: util.base64url.decode("ADuEaC75luRirAT79o0ZoQ"),
      keyLength: 16
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EC-SHA256 #2 [Raw ECDH P-256 to implied 256-bit secret]",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("7zbcQ6Fdncg6rLODr7kf8LKLi3gG97w9TDLtb015yu8"),
        x: util.base64url.decode("S5n2_0SoNTscyrut1NQGPCpwmWtvHxpZOwqJXkg_s4w"),
        y: util.base64url.decode("SS7aA0CHkIeIJNWRDVG3TndlHgGDpBe1itliHNJf0t0")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("YHgubzHrfUD4iNc1-K0XqtZDtIdviLirkP9Px2sMnFU"),
        y: util.base64url.decode("KNJTFg1mCIkpRtTF3a6OgBpjz272RiUtlfNB3vuAfrE")
      },
      secret: util.base64url.decode("ADuEaC75luRirAT79o0ZoY-3T4ad-H3yTN_PIeIZR4Q")
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS ED-SHA384 #1 [Raw ECDH P-384 to 384-bit secret]",
      private: {
        kty: "EC",
        crv: "P-384",
        d: util.base64url.decode("mFebnPmzDenxEVDpMEM5o_yJrCEX0UkJim1BKrICGuAanfJIjzZ4n5sgj1R780wa"),
        x: util.base64url.decode("1NC6nwSAOFxtcLR9FSsx_Q0wLQ336ZP6kNpFqqRvI8Kdod6qdfOi2Ap21JYUWj3f"),
        y: util.base64url.decode("LyrO6VSCuek3JCiNm3N3XgUCyiuBAi6fpZuotuInm6WBvnB8zWPUzLUKOkIOsu5z")
      },
      public: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("JGFpvixNv7B1DVspsNQumCFjWBoFEXdn6N8qwZ0j2HMwAzqF8Ohn3OzCGSY9sSjx"),
        y: util.base64url.decode("g9CSJXuFh6O30gZO3UqhScYp6D8sHixcpzZZlBBByyu2qjxfx5p6NeTHfjiCkEnx")
      },
      secret: util.base64url.decode("uCwsJVPdOdkfXpQz-9motAgAXUEDxsztn3SKXdZPM9bwVDexXXIPH9PIRp_YDi20"),
      keyLength: 48
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS ED-SHA384 #1 [Raw ECDH P-384 to 256-bit secret]",
      private: {
        kty: "EC",
        crv: "P-384",
        d: util.base64url.decode("mFebnPmzDenxEVDpMEM5o_yJrCEX0UkJim1BKrICGuAanfJIjzZ4n5sgj1R780wa"),
        x: util.base64url.decode("1NC6nwSAOFxtcLR9FSsx_Q0wLQ336ZP6kNpFqqRvI8Kdod6qdfOi2Ap21JYUWj3f"),
        y: util.base64url.decode("LyrO6VSCuek3JCiNm3N3XgUCyiuBAi6fpZuotuInm6WBvnB8zWPUzLUKOkIOsu5z")
      },
      public: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("JGFpvixNv7B1DVspsNQumCFjWBoFEXdn6N8qwZ0j2HMwAzqF8Ohn3OzCGSY9sSjx"),
        y: util.base64url.decode("g9CSJXuFh6O30gZO3UqhScYp6D8sHixcpzZZlBBByyu2qjxfx5p6NeTHfjiCkEnx")
      },
      secret: util.base64url.decode("uCwsJVPdOdkfXpQz-9motAgAXUEDxsztn3SKXdZPM9Y"),
      keyLength: 32
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS ED-SHA384 #1 [Raw ECDH P-384 to 128-bit secret]",
      private: {
        kty: "EC",
        crv: "P-384",
        d: util.base64url.decode("mFebnPmzDenxEVDpMEM5o_yJrCEX0UkJim1BKrICGuAanfJIjzZ4n5sgj1R780wa"),
        x: util.base64url.decode("1NC6nwSAOFxtcLR9FSsx_Q0wLQ336ZP6kNpFqqRvI8Kdod6qdfOi2Ap21JYUWj3f"),
        y: util.base64url.decode("LyrO6VSCuek3JCiNm3N3XgUCyiuBAi6fpZuotuInm6WBvnB8zWPUzLUKOkIOsu5z")
      },
      public: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("JGFpvixNv7B1DVspsNQumCFjWBoFEXdn6N8qwZ0j2HMwAzqF8Ohn3OzCGSY9sSjx"),
        y: util.base64url.decode("g9CSJXuFh6O30gZO3UqhScYp6D8sHixcpzZZlBBByyu2qjxfx5p6NeTHfjiCkEnx")
      },
      secret: util.base64url.decode("uCwsJVPdOdkfXpQz-9motA"),
      keyLength: 16
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS ED-SHA384 #1 [Raw ECDH P-384 to implicit 384-bit secret]",
      private: {
        kty: "EC",
        crv: "P-384",
        d: util.base64url.decode("mFebnPmzDenxEVDpMEM5o_yJrCEX0UkJim1BKrICGuAanfJIjzZ4n5sgj1R780wa"),
        x: util.base64url.decode("1NC6nwSAOFxtcLR9FSsx_Q0wLQ336ZP6kNpFqqRvI8Kdod6qdfOi2Ap21JYUWj3f"),
        y: util.base64url.decode("LyrO6VSCuek3JCiNm3N3XgUCyiuBAi6fpZuotuInm6WBvnB8zWPUzLUKOkIOsu5z")
      },
      public: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("JGFpvixNv7B1DVspsNQumCFjWBoFEXdn6N8qwZ0j2HMwAzqF8Ohn3OzCGSY9sSjx"),
        y: util.base64url.decode("g9CSJXuFh6O30gZO3UqhScYp6D8sHixcpzZZlBBByyu2qjxfx5p6NeTHfjiCkEnx")
      },
      secret: util.base64url.decode("uCwsJVPdOdkfXpQz-9motAgAXUEDxsztn3SKXdZPM9bwVDexXXIPH9PIRp_YDi20")
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EE-SHA512 #3 [Raw ECDH P-521 to 512-bit secret]",
      private: {
        kty: "EC",
        crv: "P-521",
        d: util.base64url.decode("AV7JCqhoOnTnX1_T9KSFBlSkZJWbzBaTvkRlNp83SdpbKQS3JgTgPDNtMONaXjyjjk4ec3A5QFLDBBjVrpFEl1vf"),
        x: util.base64url.decode("AaETIgjyjW-AXKXKOL_JkwtIgvus4-CQQPBKp5jqf8oDX2r4za7Uq-z6yic7ozGqpz0gtELGyJqU10YLxYK34wMp"),
        y: util.base64url.decode("AXBbywfS_ivasfDsuNBbLgxRLnrWJNsHiT1fMivgsMHwYTJcz-8FKYvj1dvJN4bnOWvGvgsRds5u0WIofsTYKKuw")
      },
      public: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("AHo_VxE69e2yc41ejRGgX52I-ZkwBno0x0QB2Japx135jHZ2x-68R_9TYFbE7unj4l7dOz3BznKVErErwTjUbieW"),
        y: util.base64url.decode("AHTQuOcIhd6PJo2oyCgxo15xDWsZf6SkSlW5Vt2buNuwqnoErGTPpEU8ptcmUqDsKRKrO5uR6PGyPwDFY3LpKYKH")
      },
      secret: util.base64url.decode("ABjsN13mS11qiAJqPR9qnoUMyN1bRdMLthuKNqVYHEoAUhQoYsSaONbmdbaKXWF6Evn-IxD7KZOdCU-4FlRWOA"),
      keyLength: 64
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EE-SHA512 #3 [Raw ECDH P-521 to 256-bit secret]",
      private: {
        kty: "EC",
        crv: "P-521",
        d: util.base64url.decode("AV7JCqhoOnTnX1_T9KSFBlSkZJWbzBaTvkRlNp83SdpbKQS3JgTgPDNtMONaXjyjjk4ec3A5QFLDBBjVrpFEl1vf"),
        x: util.base64url.decode("AaETIgjyjW-AXKXKOL_JkwtIgvus4-CQQPBKp5jqf8oDX2r4za7Uq-z6yic7ozGqpz0gtELGyJqU10YLxYK34wMp"),
        y: util.base64url.decode("AXBbywfS_ivasfDsuNBbLgxRLnrWJNsHiT1fMivgsMHwYTJcz-8FKYvj1dvJN4bnOWvGvgsRds5u0WIofsTYKKuw")
      },
      public: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("AHo_VxE69e2yc41ejRGgX52I-ZkwBno0x0QB2Japx135jHZ2x-68R_9TYFbE7unj4l7dOz3BznKVErErwTjUbieW"),
        y: util.base64url.decode("AHTQuOcIhd6PJo2oyCgxo15xDWsZf6SkSlW5Vt2buNuwqnoErGTPpEU8ptcmUqDsKRKrO5uR6PGyPwDFY3LpKYKH")
      },
      secret: util.base64url.decode("ABjsN13mS11qiAJqPR9qnoUMyN1bRdMLthuKNqVYHEo"),
      keyLength: 32
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EE-SHA512 #3 [Raw ECDH P-521 to 128-bit secret]",
      private: {
        kty: "EC",
        crv: "P-521",
        d: util.base64url.decode("AV7JCqhoOnTnX1_T9KSFBlSkZJWbzBaTvkRlNp83SdpbKQS3JgTgPDNtMONaXjyjjk4ec3A5QFLDBBjVrpFEl1vf"),
        x: util.base64url.decode("AaETIgjyjW-AXKXKOL_JkwtIgvus4-CQQPBKp5jqf8oDX2r4za7Uq-z6yic7ozGqpz0gtELGyJqU10YLxYK34wMp"),
        y: util.base64url.decode("AXBbywfS_ivasfDsuNBbLgxRLnrWJNsHiT1fMivgsMHwYTJcz-8FKYvj1dvJN4bnOWvGvgsRds5u0WIofsTYKKuw")
      },
      public: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("AHo_VxE69e2yc41ejRGgX52I-ZkwBno0x0QB2Japx135jHZ2x-68R_9TYFbE7unj4l7dOz3BznKVErErwTjUbieW"),
        y: util.base64url.decode("AHTQuOcIhd6PJo2oyCgxo15xDWsZf6SkSlW5Vt2buNuwqnoErGTPpEU8ptcmUqDsKRKrO5uR6PGyPwDFY3LpKYKH")
      },
      secret: util.base64url.decode("ABjsN13mS11qiAJqPR9qng"),
      keyLength: 16
    },
    {
      alg: "ECDH",
      desc: "NIST-CAVP KAS EE-SHA512 #3 [Raw ECDH P-521 to implied 528-bit secret]",
      private: {
        kty: "EC",
        crv: "P-521",
        d: util.base64url.decode("AV7JCqhoOnTnX1_T9KSFBlSkZJWbzBaTvkRlNp83SdpbKQS3JgTgPDNtMONaXjyjjk4ec3A5QFLDBBjVrpFEl1vf"),
        x: util.base64url.decode("AaETIgjyjW-AXKXKOL_JkwtIgvus4-CQQPBKp5jqf8oDX2r4za7Uq-z6yic7ozGqpz0gtELGyJqU10YLxYK34wMp"),
        y: util.base64url.decode("AXBbywfS_ivasfDsuNBbLgxRLnrWJNsHiT1fMivgsMHwYTJcz-8FKYvj1dvJN4bnOWvGvgsRds5u0WIofsTYKKuw")
      },
      public: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("AHo_VxE69e2yc41ejRGgX52I-ZkwBno0x0QB2Japx135jHZ2x-68R_9TYFbE7unj4l7dOz3BznKVErErwTjUbieW"),
        y: util.base64url.decode("AHTQuOcIhd6PJo2oyCgxo15xDWsZf6SkSlW5Vt2buNuwqnoErGTPpEU8ptcmUqDsKRKrO5uR6PGyPwDFY3LpKYKH")
      },
      secret: util.base64url.decode("ABjsN13mS11qiAJqPR9qnoUMyN1bRdMLthuKNqVYHEoAUhQoYsSaONbmdbaKXWF6Evn-IxD7KZOdCU-4FlRWOMh1")
    },

    // ECDH + Concat
    {
      alg: "ECDH-CONCAT",
      desc: "NIST-CAVP KAS EC-SHA256 #2 [ECDH + Concat KDF P-256 to 128-bit secret]",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("7zbcQ6Fdncg6rLODr7kf8LKLi3gG97w9TDLtb015yu8"),
        x: util.base64url.decode("S5n2_0SoNTscyrut1NQGPCpwmWtvHxpZOwqJXkg_s4w"),
        y: util.base64url.decode("SS7aA0CHkIeIJNWRDVG3TndlHgGDpBe1itliHNJf0t0")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("YHgubzHrfUD4iNc1-K0XqtZDtIdviLirkP9Px2sMnFU"),
        y: util.base64url.decode("KNJTFg1mCIkpRtTF3a6OgBpjz272RiUtlfNB3vuAfrE")
      },
      otherInfo: util.base64url.decode("Q0FWU2lkobLD1OX5smD5s6RlkiuyGR3WDDxpGRL3BwwPwqR-JIWWOYL9tIbcYms"),
      secret: util.base64url.decode("UyctrRM1IzW8LcYccie99w"),
      keyLength: 16
    },
    {
      alg: "ECDH-CONCAT",
      desc: "NIST-CAVP KAS ED-SHA384 #1 [ECDH + Concat P-384 to 192-bit secret]",
      private: {
        kty: "EC",
        crv: "P-384",
        d: util.base64url.decode("mFebnPmzDenxEVDpMEM5o_yJrCEX0UkJim1BKrICGuAanfJIjzZ4n5sgj1R780wa"),
        x: util.base64url.decode("1NC6nwSAOFxtcLR9FSsx_Q0wLQ336ZP6kNpFqqRvI8Kdod6qdfOi2Ap21JYUWj3f"),
        y: util.base64url.decode("LyrO6VSCuek3JCiNm3N3XgUCyiuBAi6fpZuotuInm6WBvnB8zWPUzLUKOkIOsu5z")
      },
      public: {
        kty: "EC",
        crv: "P-384",
        x: util.base64url.decode("JGFpvixNv7B1DVspsNQumCFjWBoFEXdn6N8qwZ0j2HMwAzqF8Ohn3OzCGSY9sSjx"),
        y: util.base64url.decode("g9CSJXuFh6O30gZO3UqhScYp6D8sHixcpzZZlBBByyu2qjxfx5p6NeTHfjiCkEnx")
      },
      otherInfo: util.base64url.decode("Q0FWU2lkobLD1OXjPitYKRnMHxfHmXEulECZpK3D3LYrcaA_TRXUiAVti2K33eo"),
      secret: util.base64url.decode("CwsCnGSlB0mg_yRjf8Lif7y0-IOZhVDM"),
      keyLength: 24
    },
    {
      alg: "ECDH-CONCAT",
      desc: "NIST-CAVP KAS EE-SHA512 #3 [ECDH + Concat P-521 to 256-bit secret]",
      private: {
        kty: "EC",
        crv: "P-521",
        d: util.base64url.decode("AV7JCqhoOnTnX1_T9KSFBlSkZJWbzBaTvkRlNp83SdpbKQS3JgTgPDNtMONaXjyjjk4ec3A5QFLDBBjVrpFEl1vf"),
        x: util.base64url.decode("AaETIgjyjW-AXKXKOL_JkwtIgvus4-CQQPBKp5jqf8oDX2r4za7Uq-z6yic7ozGqpz0gtELGyJqU10YLxYK34wMp"),
        y: util.base64url.decode("AXBbywfS_ivasfDsuNBbLgxRLnrWJNsHiT1fMivgsMHwYTJcz-8FKYvj1dvJN4bnOWvGvgsRds5u0WIofsTYKKuw")
      },
      public: {
        kty: "EC",
        crv: "P-521",
        x: util.base64url.decode("AHo_VxE69e2yc41ejRGgX52I-ZkwBno0x0QB2Japx135jHZ2x-68R_9TYFbE7unj4l7dOz3BznKVErErwTjUbieW"),
        y: util.base64url.decode("AHTQuOcIhd6PJo2oyCgxo15xDWsZf6SkSlW5Vt2buNuwqnoErGTPpEU8ptcmUqDsKRKrO5uR6PGyPwDFY3LpKYKH")
      },
      otherInfo: util.base64url.decode("Q0FWU2lkobLD1OVkvTMB9TCliA8WmP78okVMUh2bNRp_hIkxQGqb72z69Af2J0k"),
      secret: util.base64url.decode("0ufS0xG13qfXkclzaWbtcrKzDMYTJY6jSpq8omaSCZA"),
      keyLength: 32
    },

    // ECDH + HKDF
    {
      alg: "ECDH-HKDF",
      desc: "Constructed P-256 + HKDF to 256-bit secret",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
        x: util.base64url.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"),
        y: util.base64url.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"),
        y: util.base64url.decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck")
      },
      secret: util.base64url.decode("V7JQ34iR8BffRJir0sZoHuPjFoejiqb2U9_MoVLMVio"),
      keyLength: 32
    },
    {
      alg: "ECDH-HKDF",
      desc: "Constructed P-256 + HKDF to 128-bit secret",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
        x: util.base64url.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"),
        y: util.base64url.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"),
        y: util.base64url.decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck")
      },
      secret: util.base64url.decode("V7JQ34iR8BffRJir0sZoHg"),
      keyLength: 16
    },
    {
      alg: "ECDH-HKDF",
      desc: "Constructed P-256 + HKDF to implied 256-bit secret",
      private: {
        kty: "EC",
        crv: "P-256",
        d: util.base64url.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"),
        x: util.base64url.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"),
        y: util.base64url.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
      },
      public: {
        kty: "EC",
        crv: "P-256",
        x: util.base64url.decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"),
        y: util.base64url.decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck")
      },
      secret: util.base64url.decode("V7JQ34iR8BffRJir0sZoHuPjFoejiqb2U9_MoVLMVio")
    }
  ];
  deriveVectors.forEach(function(v) {
    if (bowser.safari && "P-521" === v.private.crv) {
      return;
    }

    var deriverunner = function() {
      var pubKey = v.public,
          privKey = v.private,
          secret = v.secret,
          keyLen = v.keyLength;

      var props = {
        public: pubKey
      };
      if (keyLen) {
        props.length = keyLen;
      }
      if (v.otherInfo) {
        props.otherInfo = v.otherInfo;
      }

      var promise = algorithms.derive(v.alg, privKey, props);
      promise = promise.then(function(result) {
        assert.equal(result.toString("hex"), secret.toString("hex"));
      });
      return promise;
    };

    it("performs " + v.alg + " (" + v.desc + ") derivation", deriverunner);
  });

  var encdecVectors = [
    {
      alg: "ECDH-ES",
      desc: "RFC 7518 Appendix C: Example ECDH-ES Key Agreement Computation",
      local: {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0"),
        "y": util.base64url.decode("SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"),
        "d": util.base64url.decode("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo")
      },
      remote: {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"),
        "y": util.base64url.decode("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"),
        "d": util.base64url.decode("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
      },
      enc: "A128GCM",
      apu: util.base64url.decode("QWxpY2U"),
      apv: util.base64url.decode("Qm9i"),
      secret: util.base64url.decode("VqqN6vgjbSBcIijNcacQGg"),
      direct: true,
      once: true
    },
    {
      alg: "ECDH-ES+A128KW",
      desc: "Pre-generated ECDH Ephemeral-Static with AES-128-KW Key Wrapping",
      local: {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("QAc9AODpp43FtVs0OqmiAE7MI4mTnNZlQikDWVoWE3Y"),
        "y": util.base64url.decode("t2fphG7NiaWMqSuc4DnyZtA7rBt5FjOhB-ZOUaF9KNQ"),
        "d": util.base64url.decode("6rjahZxevjYQ7UmqSUEQ5fK8YVZ-QCQcVtbtC63xl3w")
      },
      remote: {
        "kty": "EC",
        "crv": "P-256",
        "x": util.base64url.decode("wE6lLi8DqbkYrJIhylztpu8OsTetXE4Q5tRAkFemtP8"),
        "y": util.base64url.decode("ei1CSptDQkYtzT2ThVc_EO84SbYDI5ZWVX6mxmBzSvY"),
        "d": util.base64url.decode("J1yGL-36TcYasGxBS3lSHjgB2yWnfnRAZ-BEcx5voxk")
      },
      enc: "A128GCM",
      apu: util.base64url.decode("QWxpY2U"),
      apv: util.base64url.decode("Qm9i"),
      cek: util.base64url.decode("XGBmqfGFXBSUyYQabuznow"),
      secret: util.base64url.decode("EPc3n2hbJtUeSAyDhfAIbP7wKRsdE2Gn")
    }
  ];
  encdecVectors.forEach(function(v) {
    if (bowser.safari && "P-521" === v.local.crv) {
      return;
    }

    var encrunner = function() {
      var spk = omit(v.remote, "d"),
          epk = v.local,
          cek = v.cek,
          secret = v.secret;
      var props = {
        alg: v.alg,
        enc: v.enc,
        epk: epk,
        apu: v.apu,
        apv: v.apv
      };
      var promise = algorithms.encrypt(v.alg, spk, cek, props);
      promise = promise.then(function(result) {
        assert.equal(result.data.toString("hex"), secret.toString("hex"));
        if ("direct" in v) {
          assert.equal(result.direct, v.direct);
        } else {
          assert.ok(!("direct" in result));
        }

        if ("once" in v) {
          assert.equal(result.once, v.once);
        } else {
          assert.ok(!("once" in result));
        }
      });
      return promise;
    };
    var decrunner = function() {
      var epk = omit(v.remote, "d"),
          spk = v.local,
          cek = v.cek,
          secret = v.secret;
      var props = {
        alg: v.alg,
        enc: v.enc,
        epk: epk,
        apu: v.apu,
        apv: v.apv
      };
      var promise = algorithms.decrypt(v.alg, spk, secret, props);
      promise = promise.then(function(result) {
        if (!cek) {
          assert.equal(result.toString("hex"), secret.toString("hex"));
        } else {
          assert.equal(result.toString("hex"), cek.toString("hex"));
        }
      });
      return promise;
    };

    it("performs " + v.alg + "(" + v.desc + ") key wrap", encrunner);
    it("performs " + v.alg + "(" + v.desc + ") key unwrap", decrunner);
  });
});
