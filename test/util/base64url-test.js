/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var utils = {
  base64url: require("../../lib/util/base64url.js")
};

describe("util/base64url", function() {
  it("should encode a node.js Buffer", function() {
    var input = Buffer.from("‹hello world!›", "utf8");
    var output = utils.base64url.encode(input);
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode an ArrayBuffer", function() {
    var input = new Uint8Array([226, 128, 185, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 226, 128, 186]).
                buffer;
    var output = utils.base64url.encode(input);
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode an ArrayBufferView", function() {
    var input = new Uint8Array([226, 128, 185, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 226, 128, 186]);
    var output = utils.base64url.encode(input);
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode an array", function() {
    var input = [226, 128, 185, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 226, 128, 186];
    var output = utils.base64url.encode(input);
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode a (utf8) string", function() {
    var input = "‹hello world!›";
    var output = utils.base64url.encode(input);
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode a string with a specified encoding", function() {
    var input, output;

    input = "‹hello world!›";
    output = utils.base64url.encode(input, "utf8");
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");

    input = "\xe2\x80\xb9hello world!\xe2\x80\xba";
    output = utils.base64url.encode(input, "binary");
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");

    input = "e280b968656c6c6f20776f726c6421e280ba";
    output = utils.base64url.encode(input, "hex");
    assert.equal(output, "4oC5aGVsbG8gd29ybGQh4oC6");
  });

  it("should encode the rainbow!", function() {
    var input, output;

    input = "3dfbff39ebbe35db7d31cb3c2dbafb29aaba259a79218a381d79f71969b61559751149340d38f30928b2051871010830";
    output = utils.base64url.encode(input, "hex");
    assert.equal(output, "Pfv_Oeu-Ndt9Mcs8Lbr7Kaq6JZp5IYo4HXn3GWm2FVl1EUk0DTjzCSiyBRhxAQgw");
  });

  it("should encode without padding", function() {
    var input, output;
    input = "hello!!";
    output = utils.base64url.encode(input, "utf8");
    assert.equal(output, "aGVsbG8hIQ");
  });

  it("should decode a string to a node.js Buffer", function() {
    var input, output;

    input = "4oC5aGVsbG8gd29ybGQh4oC6";
    output = utils.base64url.decode(input);

    var expected = Buffer.from([226, 128, 185, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 33, 226, 128, 186]);
    assert.deepEqual(output, expected);
  });

  it("should decode the rainbow!", function() {
    var input, output;

    input = "Pfv_Oeu-Ndt9Mcs8Lbr7Kaq6JZp5IYo4HXn3GWm2FVl1EUk0DTjzCSiyBRhxAQgw";
    output = utils.base64url.decode(input).toString("hex");
    assert.equal(output, "3dfbff39ebbe35db7d31cb3c2dbafb29aaba259a79218a381d79f71969b61559751149340d38f30928b2051871010830");
  });
});
