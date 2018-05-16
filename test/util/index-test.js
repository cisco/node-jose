/**
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;
var UTIL = require("../../lib/util");

describe("util", function() {
  describe("#randomBytes", function() {
    it("returns a Buffer of randomized bytes", function() {
      var result;

      result = UTIL.randomBytes(12);
      assert.equal(Buffer.isBuffer(result), true);
      assert.equal(result.length, 12);

      result = UTIL.randomBytes(41);
      assert.equal(Buffer.isBuffer(result), true);
      assert.equal(result.length, 41);

      result = UTIL.randomBytes(4096);
      assert.equal(Buffer.isBuffer(result), true);
      assert.equal(result.length, 4096);
    });
  });

  describe("#asBuffer", function() {
    it("returns a Buffer for an Array", function() {
      var input, output;

      input = new Array(256);
      for (var idx = 0; idx < input.length; idx++) {
        input[idx] = idx % 256;
      }
      output = UTIL.asBuffer(input);
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, Buffer.from(input));
    });
    it("returns a Buffer for an Uint8Array", function() {
      var input, output;

      input = new Uint8Array(256);
      for (var idx = 0; idx < input.length; idx++) {
        input[idx] = idx % 256;
      }
      output = UTIL.asBuffer(input);
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, Buffer.from(input));
    });
    it("returns a Buffer for an ArrayBuffer", function() {
      var input, output;

      input = new Uint8Array(256);
      for (var idx = 0; idx < input.length; idx++) {
        input[idx] = idx % 256;
      }
      output = UTIL.asBuffer(input.buffer);
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, Buffer.from(input));
    });
    it("returns a Buffer for some other TypedArray", function() {
      var input, output;

      input = new Uint8Array(256);
      for (var idx = 0; idx < input.length; idx++) {
        input[idx] = idx % 256;
      }
      output = UTIL.asBuffer(new Float32Array(input.buffer));
      assert.equal(Buffer.isBuffer(output), true);
    });
    it("retuns a Buffer for a binary string", function() {
      var input, output;

      input = new Array(256);
      for (var idx = 0; idx < input.length; idx++) {
        input[idx] = String.fromCharCode(idx % 256);
      }
      output = UTIL.asBuffer(input.map(function(c) { return String.fromCharCode(c); }).join(""));
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, Buffer.from(input));
    });
    it("retuns a Buffer for a text string", function() {
      var input, output;

      input = "hello there, world!";
      output = UTIL.asBuffer(input, "utf8");
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, Buffer.from(input, "utf8"));
    });
    it("returns a Buffer for a base64url string", function() {
      var input, output;

      input = "aGVsbG8gdGhlcmUsIHdvcmxkIQ";
      output = UTIL.asBuffer(input, "base64url");
      assert.equal(Buffer.isBuffer(output), true);
      assert.deepEqual(output, UTIL.base64url.decode(input));
    });
  });
});
