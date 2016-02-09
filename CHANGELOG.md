<a name="0.7.1"></a>
## [0.7.1](https://github.com/cisco/node-jose/compare/0.7.0...0.7.1) (2016-02-09)


### Fix

* fix throws and rejects to be error objects and consistent ([89325da4b183817a7c412af98f2aa2b9dce97ff9](https://github.com/cisco/node-jose/commit/89325da4b183817a7c412af98f2aa2b9dce97ff9))
* only honor isPrivate in JWK.toJSON() if it is actually a Boolean ([9f2f813fc5a10e0d477d5c06e4e719027b6cddbb](https://github.com/cisco/node-jose/commit/9f2f813fc5a10e0d477d5c06e4e719027b6cddbb))



<a name="0.7.0"></a>
# [0.7.0](https://github.com/cisco/node-jose/compare/0.6.0...0.7.0) (2016-01-14)


### Update

* implement JWK thumbprint support [RFC 7638] ([e57384cbf84cc30d8cc0be2b1f881107c4c74577](https://github.com/cisco/node-jose/commit/e57384cbf84cc30d8cc0be2b1f881107c4c74577))
* support Microsoft Edge ([5ea3c881045388992511f61c9bfc17c8ab62f066](https://github.com/cisco/node-jose/commit/5ea3c881045388992511f61c9bfc17c8ab62f066))



<a name="0.6.0"></a>
# [0.6.0](https://github.com/cisco/node-jose/compare/0.5.2...0.6.0) (2015-12-12)


### Update

* export EC keys as PEM ([71d382ef06112dd6f71f7feec8c017b72695d20f](https://github.com/cisco/node-jose/commit/71d382ef06112dd6f71f7feec8c017b72695d20f))
* export RSA keys as PEM ([e6ef2ef9aeddb0afc92d55222ae7669c87a3f6f1](https://github.com/cisco/node-jose/commit/e6ef2ef9aeddb0afc92d55222ae7669c87a3f6f1))
* import EC and RSA keys from "raw" PEM ([f7a6dcab643209347b7bf68cb014d12e1698e8ff](https://github.com/cisco/node-jose/commit/f7a6dcab643209347b7bf68cb014d12e1698e8ff))
* import EC and RSA "raw" private keys from DER ([f3cd2679317cec5a8a80f0634f777e4bc8ace4cd](https://github.com/cisco/node-jose/commit/f3cd2679317cec5a8a80f0634f777e4bc8ace4cd))
* harmonize output from JWE.decrypt and JWS.verify ([ed0ea52e4fc4cc70920f2ce39bda11b09c45f214](https://github.com/cisco/node-jose/commit/ed0ea52e4fc4cc70920f2ce39bda11b09c45f214))


<a name="0.5.2"></a>
## [0.5.2](https://github.com/cisco/node-jose/compare/0.5.1...0.5.2) (2015-11-30)


### Fix

* polyfill should not override native Promise ([7ff0d4e6828e9b21ed12f98118a630d195ed7c9b](https://github.com/cisco/node-jose/commit/7ff0d4e6828e9b21ed12f98118a630d195ed7c9b))

### Doc

* fix wrong decryption sample code in README.md ([733d23f012b90a1b15f5474b7d25b7523d1a6e66](https://github.com/cisco/node-jose/commit/733d23f012b90a1b15f5474b7d25b7523d1a6e66))

### Build

* add code coverage for node + browsers ([4638bd52f81d2163df0aea71e09c4bd564dcee14](https://github.com/cisco/node-jose/commit/4638bd52f81d2163df0aea71e09c4bd564dcee14))
* add code coverage for node + browsers ([df7d8cd0e28e6f381194fb27ea9b5df3a2968b60](https://github.com/cisco/node-jose/commit/df7d8cd0e28e6f381194fb27ea9b5df3a2968b60))


<a name="0.5.1"></a>
## [0.5.1](https://github.com/cisco/node-jose/compare/0.5.0...0.5.1) (2015-11-19)


### Fix

* 'stack exceeded' error on node.js 0.10 ([4ad481210adae7cdc2a06a6c25ddcefe33eff395](https://github.com/cisco/node-jose/commit/4ad481210adae7cdc2a06a6c25ddcefe33eff395))
* address errors with setImmediate in IE ([caa32813dfb059955f0069f76cfee44c40c35c55](https://github.com/cisco/node-jose/commit/caa32813dfb059955f0069f76cfee44c40c35c55))

### Build

* add CGMKW test ([3643a9c5bc476c9ff2423858c772401b0b06557d](https://github.com/cisco/node-jose/commit/3643a9c5bc476c9ff2423858c772401b0b06557d))
* expand the saucelabs platforms ([5eef84db07cfb8069853b2ee072d5888aaf16106](https://github.com/cisco/node-jose/commit/5eef84db07cfb8069853b2ee072d5888aaf16106))


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
