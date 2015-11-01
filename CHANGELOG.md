<a name="0.5.0"></a>
# [0.5.0](https://github.com/cisco/node-jose/compare/0.4.0...0.5.0) (2015-10-31)


### Update

* Support extra fields and x5t generation when importing a cert ([0d52aa5dabe6af29a08c2e299fc6be9ff5e81fca](https://github.com/cisco/node-jose/commit/0d52aa5dabe6af29a08c2e299fc6be9ff5e81fca))
* Support deprecated `A*CBC+HS*` algorithms (aka the "plus" algorithms) ([d682e2920eeb9ff6599d7115f2dfbd705104603f](https://github.com/cisco/node-jose/commit/d682e2920eeb9ff6599d7115f2dfbd705104603f))

### Fix

* base64url does not work on IE  ([1ab757265ff2a160e49e870231590b2a47a4537b](https://github.com/cisco/node-jose/commit/1ab757265ff2a160e49e870231590b2a47a4537b)), closes [#16](https://github.com/cisco/node-jose/issues/16)
* When an assumed key is provided, use it over any others ([9df51df13c153958661b7f76c7f1f2c3d322c109](https://github.com/cisco/node-jose/commit/9df51df13c153958661b7f76c7f1f2c3d322c109)), fixes [#14](https://github.com/cisco/node-jose/issues/14)


<a name="0.4.0"></a>
# [0.4.0](https://github.com/cisco/node-jose/compare/0.3.1...0.4.0) (2015-10-12)


### Breaking

* Use external implementation of base64url ([78009311235006e1a2c76e1dadd78e200d4f954b](https://github.com/cisco/node-jose/commit/78009311235006e1a2c76e1dadd78e200d4f954b))

### Update

* Import a RSA or EC key from ASN.1 (PEM or DER) ([cab7fc1e6e2551e5bebda0ec0ab0e6340ed564f3](https://github.com/cisco/node-jose/commit/cab7fc1e6e2551e5bebda0ec0ab0e6340ed564f3))
* Include key in JWS.verify result ([d1267b29a120499d3a86b7213e7db6855c61d6c3](https://github.com/cisco/node-jose/commit/d1267b29a120499d3a86b7213e7db6855c61d6c3))


<a name="0.3.1"></a>
# [0.3.1](https://github.com/cisco/node-jose/compare/0.3.0...0.3.1) (2015-10-06)


### Fix

* JWE encryption fails for ECDH keys  ([3ecb7be38c237b09866b1ab3e7525dd6351e8153](https://github.com/cisco/node-jose/commit/3ecb7be38c237b09866b1ab3e7525dd6351e8153)), closes [#3](https://github.com/cisco/node-jose/issues/3)

* proper name for file header ([6364553ddf581c7628f4ea79877fec57545dff92](https://github.com/cisco/node-jose/commit/6364553ddf581c7628f4ea79877fec57545dff92))

### Update

* provide a generic parse() method to see header(s) and generically unwrap ([ecc859691395114cd7db644171e2c1b2e1015c8b](https://github.com/cisco/node-jose/commit/ecc859691395114cd7db644171e2c1b2e1015c8b))
* support parsing Buffer ([580f763d0dfc63d5f6fdbde3bfec6f52a5218636](https://github.com/cisco/node-jose/commit/580f763d0dfc63d5f6fdbde3bfec6f52a5218636))

### Doc

* fix code blocks to render as blocks consistently ([5f1a7ace4c8871065c3a9d09d8f38f09b8096413](https://github.com/cisco/node-jose/commit/5f1a7ace4c8871065c3a9d09d8f38f09b8096413))
* update readme to reflect NPM publication ([936058bc9ff19049327486842335324e34f1d73e](https://github.com/cisco/node-jose/commit/936058bc9ff19049327486842335324e34f1d73e))

### Build

* browserify is only a devDependency ([17880c401daea03f26af6438b2681232e3654a58](https://github.com/cisco/node-jose/commit/17880c401daea03f26af6438b2681232e3654a58))


<a name="0.3.0"></a>
# [0.3.0] (2015-09-11)

Initial public release.
