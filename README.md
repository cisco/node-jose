# node-jose #

A JavaScript implementation of the JSON Object Signing and Encryption (JOSE) for current web browsers and node.js-based servers.  This library implements (wherever possible) all algorithms, formats, and options in [JWS](https://tools.ietf.org/html/rfc7515 "Jones, M., J. Bradley and N. Sakimura, 'JSON Web Signature (JWS)' RFC 7515, May 2015"), [JWE](https://tools.ietf.org/html/rfc7516 "Jones, M. and J. Hildebrand 'JSON Web Encryption (JWE)', RFC 7516, May 2015"), [JWK](https://tools.ietf/html/rfc7517 "Jones, M., 'JSON Web Key (JWK)', RFC 7517, May 2015"), and [JWA](https://tools.ietf/html/rfc7518 "Jones, M., 'JSON Web Algorithms (JWA)', RFC 7518, May 2015") and uses native cryptographic support ([WebCrypto API](http://www.w3.org/TR/WebCryptoAPI/) or node.js' "[crypto](https://nodejs.org/api/crypto.html)" module) where feasible.

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->


- [Installing](#installing)
- [Basics](#basics)
- [Keys and Key Stores](#keys-and-key-stores)
  - [Obtaining a KeyStore](#obtaining-a-keystore)
  - [Exporting a KeyStore](#exporting-a-keystore)
  - [Retrieving Keys](#retrieving-keys)
  - [Searching for Keys](#searching-for-keys)
  - [Managing Keys](#managing-keys)
  - [Importing and Exporting a Single Key](#importing-and-exporting-a-single-key)
- [Signatures](#signatures)
  - [Signing Content](#signing-content)
  - [Verifying a JWS](#verifying-a-jws)
- [Encryption](#encryption)
  - [Encrypting Content](#encrypting-content)
  - [Decrypting a JWE](#decrypting-a-jwe)
- [Useful Utilities](#useful-utilities)
  - [Converting to Buffer](#converting-to-buffer)
  - [URI-Safe Base64](#uri-safe-base64)
  - [Random Bytes](#random-bytes)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Installing ##

To install the latest from [NPM](https://npmjs.com/):

```
  npm install node-jose
```

Or to install a specific release:

```
  npm install node-jose@0.3.0
```

Alternatively, the latest unpublished code can be installed directly from the repository:

```
  npm install git+ssh://git@github.com:cisco/node-jose.git
```

## Basics ##

Require the library as normal:

```
var jose = require('node-jose');
```

This library uses [Promises](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise) for nearly every operation.

This library supports [Browserify](http://browserify.org/).  To use in a web browser, `require('node-kms')` and bundle with the rest of your app.

The content to be signed/encrypted or returned from being verified/decrypted are [Buffer](https://nodejs.org/api/buffer.html) objects.

## Keys and Key Stores ##

The `jose.JWK` namespace deals with JWK and JWK-sets.

* `jose.JWK.Key` is a logical representation of a JWK, and is the "raw" entry point for various cryptographic operations (e.g., sign, verify, encrypt, decrypt).
* `jose.JWK.KeyStore` represents a collection of Keys.

Creating a JWE or JWS ultimately require one or more explicit Key objects.

Processing a JWE or JWS relies on a KeyStore.

### Obtaining a KeyStore ###
To create an empty keystore:

```
keystore = jose.JWK.createKeyStore();
```

To import a JWK-set as a keystore:

```
// {input} is a String or JSON object representing the JWK-set
jose.JWK.asKeyStore(input).
     then(function(result) {
       // {result} is a jose.JWK.KeyStore
       keystore = result;
     });
```

### Exporting a KeyStore ###

To export the public keys of a keystore as a JWK-set:

```
output = keystore.toJSON();
```

To export **all** the keys of a keystore:

```
output = keystore.toJSON(true);
```

### Retrieving Keys ###

To retrieve a key from a keystore:

```
// by 'kid'
key = keystore.get(kid);
```

This retrieves the first key that matches the given {kid}.  If multiple keys have the same {kid}, you can further narrow what to retrieve:

```
// ... and by 'kty'
key = keystore.get(kid, { kty: 'RSA' });

// ... and by 'use'
key = keystore.get(kid, { use: 'enc' });

// ... and by 'alg'
key = keystore.get(kid, { use: 'RSA-OAEP' });

// ... and by 'kty' and 'use'
key = keystore.get(kid, { kty: 'RSA', use: 'enc' });

// same as above, but with a single {props} argument
key = keystore.get({ kid: kid, kty: 'RSA', use: 'enc' });
```

### Searching for Keys ###

To retrieve all the keys from a keystore:

```
everything = keystore.all();
```

`all()` can be filtered much like `get()`:

```
// filter by 'kid'
everything = keystore.all({ kid: kid });

// filter by 'kty'
everything = keystore.all({ kty: 'RSA' });

// filter by 'use'
everything = keystore.all({ use: 'enc' });

// filter by 'alg'
everything = keystore.all({ alg: 'RSA-OAEP' });

// filter by 'kid' + 'kty' + 'alg'
everything = keystore.all({ kid: kid, kty: 'RSA', alg: 'RSA-OAEP' });
```

### Managing Keys ###

To import an existing Key (as a JSON object or Key instance):

```
// input is either a:
// *  jose.JWK.Key to copy from; or
// *  JSON object representing a JWK; or
// *  String serialization of a JWK
keystore.add(input).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });
```

To generate a new Key:

```
// first argument is the key type (kty)
// second is the key size (in bits) or named curve ('crv') for "EC"
keystore.generate("oct", 256).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });

// ... with properties
var props = {
  kid: 'gBdaS-G8RLax2qgObTD94w',
  alg: 'A256GCM',
  use: 'enc'
};
keystore.generate("oct", 256, props).
        then(function(result) {
          // {result} is a jose.JWK.Key
          key = result;
        });
```

To remove a Key from its Keystore:
```
kestyore.remove(key);
// NOTE: key.keystore does not change!!
```

### Importing and Exporting a Single Key ###

To import a single Key (as a JSON Object, or String serialized JSON Object):

```
jose.JWK.asKey(input).
        then(function(result) {
          // {result} is a jose.JWK.Key
          // {result.keystore} is a unique jose.JWK.KeyStore
        });
```

To export the public portion of a Key as a JWK:
```
var output = key.toJSON();
```

To export the public **and** private portions of a Key:
```
var output = key.toJSON(true);
```

## Signatures ##

### Signing Content ###

At its simplest, to create a JWS:

```
// {input} is a Buffer
jose.JWS.createSign(key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON object -- JWS using the JSON General Serialization
        });
```

The JWS is signed using the preferred algorithm appropriate for the given Key.  The preferred algorithm is the first item returned by `key.algorithms("sign")`.

To create a JWS using another serialization format:

```
jose.JWS.createSign({ format: 'flattened' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON object -- JWS using the JSON Flattened Serialization
        });

jose.JWS.createSign({ format: 'compact' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a String -- JWS using the Compact Serialization
        });
```

To create a JWS using a specific algorithm:
```
jose.JWS.createSign({ alg: 'PS256' }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS for a specified content type:

```
jose.JWS.createSign({ fields: { cty: 'jwk+json' } }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS from String content:

```
jose.JWS.createSign(key).
        update(input, "utf8").
        final().
        then(function(result) {
          // ....
        });
```

To create a JWS with multiple signatures:

```
// {keys} is an Array of jose.JWK.Key instances
jose.JWS.createSign(keys).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

### Verifying a JWS ###

To verify a JWS, and retrieve the payload:

```
jose.JWS.createVerify(keystore).
        verify(input).
        then(function(result) {
          // {result} is a Object with:
          // *  header: the combined 'protected' and 'unprotected' header members
          // *  payload: Buffer of the signed content
          // *  signature: Buffer of the verified signature
        });
```

To verify using an implied Key:

```
// {key} can be:
// *  jose.JWK.Key
// *  JSON object representing a JWK
jose.JWS.createVerify(key).
        verify(input).
        then(function(result) {
          // ...
        });
```

## Encryption ##

### Encrypting Content ###

At its simplest, to create a JWE:

```
// {input} is a Buffer
jose.JWE.createEncrypt(key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON Object -- JWE using the JSON General Serialization
        });
```

How the JWE content is encrypted depends on the provided Key.

* If the Key only supports content encryption algorithms, then the preferred algorithm is used to encrypt the content and the key encryption algorithm (i.e., the "alg" member) is set to "dir".  The preferred algorithm is the first item returned by `key.algorithms("encrypt")`.
* If the Key supports key management algorithms, then the JWE content is encrypted using "A128CBC-HS256" by default, and the Content Encryption Key is encrypted using the preferred algorithms for the given Key.  The preferred algorithm is the first item returned by `key.algorithms("wrap")`.


To create a JWE using a different serialization format:

```
jose.JWE.createEncrypt({ format: 'compact' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a String -- JWE using the Compact Serialization
        });

jose.JWE.createEncrypt({ format: 'flattened' }, key).
        update(input).
        final().
        then(function(result) {
          // {result} is a JSON Object -- JWE using the JSON Flattened Serialization
        });
```

To create a JWE and compressing the content before encrypting:

```
jose.JWE.createEncrypt({ zip: true }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWE for a specific content type:

```
jose.JWE.createEncrypt({ fields: { cty : 'jwk+json' } }, key).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

To create a JWE with multiple recipients:

```
// {keys} is an Array of jose.JWK.Key instances
jose.JWE.createEncrypt(keys).
        update(input).
        final().
        then(function(result) {
          // ....
        });
```

### Decrypting a JWE ###

To decrypt a JWE, and retrieve the plaintext:

```
jose.JWE.createDecrypt(keystore).
        verify(input).
        then(function(result) {
          // {result} is a Object with:
          // *  header: the combined 'protected' and 'unprotected' header members
          // *  key: Key used to decrypt
          // *  plaintext: Buffer of the decrypted content
        });
```

To decrypt a JWE using an implied key:

```
jose.JWE.createDecrypt(key).
        verify(input).
        then(function(result) {
          // ....
        });
```

## Useful Utilities ##

### Converting to Buffer ###

To convert a [Typed Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Typed_arrays), [ArrayBuffer](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/ArrayBuffer), or Array of Numbers to a Buffer:

```
buff = jose.util.asBuffer(input);
```

### URI-Safe Base64 ###

To convert from a Buffer to a base64uri-encoded String:

```
var output = jose.util.base64url.encode(input);
```

To convert a String to a base64uri-encoded String:

```
// explicit encoding
output = jose.util.base64url.encode(input, "utf8");

// implied "binary" encoding
output = jose.util.base64url.encode(input);
```

To convert a base64uri-encoded String to a Buffer:

```
var output = jose.util.base64url.decode(input);
```

To convert a base64uri-encoded String to a String:

```
output = jose.util.base64url.decode(input, "utf8");
```

### Random Bytes ###

To generate a Buffer of octets, regardless of platform:

```
// argument is size (in bytes)
var rnd = jose.util.randomBytes(32);
```

This function uses:

* `crypto.randomBytes()` on node.js
* `crypto.getRandomValues()` on modern browsers
* A PRNG based on AES and SHA-1 for older platforms
