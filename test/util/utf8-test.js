/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var utils = {
  utf8: require("../../lib/util/utf8.js")
};

describe("util/utf8", function() {
  it("should encode an ascii string unchanged", function() {
    var input = "hello world!";
    var output = utils.utf8.encode(input);
    assert.equal(output, input);
  });

  it("should encode a single UCS-2 character", function() {
    var input = "\u00a3";         // POUNDS SIGN
    var output = utils.utf8.encode(input);
    assert.equal(output, "\xc2\xa3");
  });

  it("should encode a SMP character", function() {
    var input = "\ud83d\udc4d";   // THUMBS UP SIGN
    var output = utils.utf8.encode(input);
    assert.equal(output, "\xf0\x9f\x91\x8d");
  });

  it("should encode a complex string", function() {
    var input = "For only £5.99! \ud83d\udc4d";
    var output = utils.utf8.encode(input);
    assert.equal(output, "For only \xc2\xa35.99! \xf0\x9f\x91\x8d");
  });

  it("should decode an ascii string unchanged", function() {
    var input = "hello world";
    var output = utils.utf8.decode(input);
    assert.equal(output, input);
  });

  it("should decode to a single UCS-2 character", function() {
    var input = "\xc2\xa3";     // POUNDS SIGN
    var output = utils.utf8.decode(input);
    assert.equal(output, "\u00a3");
  });

  it("should decode to a SMP character", function() {
    var input = "\xf0\x9f\x91\x8d";
    var output = utils.utf8.decode(input);
    assert.equal(output, "\ud83d\udc4d");
  });

  it("should decode a complex string", function() {
    var input = "For only \xc2\xa35.99! \xf0\x9f\x91\x8d";
    var output = utils.utf8.decode(input);
    assert.equal(output, "For only £5.99! \ud83d\udc4d");
  });
});
