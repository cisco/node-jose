/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var utils = {
  DataBuffer: require("../../lib/util/databuffer.js")
};

function assertArrayEqual(a1, a2) {
  assert.equal(a1.length, a2.length);
  for (var idx = 0; idx < a2.length; idx++) {
    assert.equal(a1[idx], a2[idx], "element " + idx + " not equal");
  }
}

describe("util/DataBuffer", function() {
  it("creates a default empty DataBuffer", function() {
    var buffer;
    buffer = new utils.DataBuffer();
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 0);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 0);
    assert.equal(buffer.available(), 16);
    assert.ok(buffer.isEmpty());
  });

  it("creates a DataBuffer from ArrayBuffer", function() {
    var input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input.buffer);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 31);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 31);
    assert.equal(buffer.available(), 0);
    assertArrayEqual(buffer.data, input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from ArrayBufferView", function() {
    var input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 31);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 31);
    assert.equal(buffer.available(), 0);
    assertArrayEqual(buffer.data, input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from nodejs Buffer", function() {
    var input = Buffer.alloc(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 31);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 31);
    assert.equal(buffer.available(), 0);
    assert.strictEqual(buffer.data, input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from an array", function() {
    var input = [104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101];

    var buffer = new utils.DataBuffer(input);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, input.length);
    assert.equal(buffer.length(), input.length);
    assert.equal(buffer.available(), 16 - input.length);
    assertArrayEqual(buffer.data.slice(0, input.length), input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from string", function() {
    var input = "hello there";

    var buffer = new utils.DataBuffer(input);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, input.length);
    assert.equal(buffer.length(), input.length);
    assert.equal(buffer.available(), 16 - input.length);

    var expected = [];
    for (var idx = 0; idx < input.length; idx++) {
      expected[idx] = input.charCodeAt(idx);
    }
    assertArrayEqual(buffer.data.slice(0, expected.length), expected);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from another DataBuffer", function() {
    var expected = [104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101];
    var input = new utils.DataBuffer(expected);

    var buffer = new utils.DataBuffer(input);
    assert.equal(buffer.growSize, 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, expected.length);
    assert.notStrictEqual(buffer.data, input.data);
    assert.equal(buffer.length(), expected.length);
    assert.equal(buffer.available(), 16 - expected.length);
    assertArrayEqual(buffer.data.slice(0, expected.length), expected);
    assert.ok(!buffer.isEmpty());
  });

  it("creates an empty DataBuffer with options", function() {
    var buffer = new utils.DataBuffer(null, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), 1014);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from ArrayBuffer with options", function() {
    var input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input.buffer, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), input.length - 10);
    assertArrayEqual(buffer.data.slice(0, input.length), input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from ArrayBufferView with options", function() {
    var input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), input.length - 10);
    assertArrayEqual(buffer.data.slice(0, input.length), input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from nodejs Buffer with options", function() {
    var input = Buffer.alloc(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer;
    buffer = new utils.DataBuffer(input, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.ok(Buffer.isBuffer(buffer.data));
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), input.length - 10);
    assert.strictEqual(buffer.data, input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from an array with options", function() {
    var input = [104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101];

    var buffer = new utils.DataBuffer(input, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), 1014);
    assertArrayEqual(buffer.data.slice(0, input.length), input);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from string with options", function() {
    var input = "hello there";

    var buffer = new utils.DataBuffer(input, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), 1014);

    var expected = [];
    for (var idx = 0; idx < input.length; idx++) {
      expected[idx] = input.charCodeAt(idx);
    }
    assertArrayEqual(buffer.data.slice(0, expected.length), expected);
    assert.ok(!buffer.isEmpty());
  });

  it("creates a DataBuffer from another DataBuffer with options", function() {
    var expected = [104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101];
    var input = new utils.DataBuffer(expected);

    var buffer = new utils.DataBuffer(input, {
      readOffset: 5,
      writeOffset: 10,
      growSize: 1024
    });
    assert.equal(buffer.growSize, 1024);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 10);
    assert.notStrictEqual(buffer.data, input.data);
    assert.equal(buffer.length(), 5);
    assert.equal(buffer.available(), 1014);
    assertArrayEqual(buffer.data.slice(0, expected.length), expected);
    assert.ok(!buffer.isEmpty());
  });

  it("returns the correct encoding for toString()", function() {
    var buffer = new utils.DataBuffer([194, 171, 104, 101, 108, 108, 111, 32, 116, 104, 101, 114, 101, 194, 187]);

    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");
    assert.equal(buffer.toString("raw"), "\xc2\xabhello there\xc2\xbb");
    assert.equal(buffer.toString("hex"), "c2ab68656c6c6f207468657265c2bb");
    assert.equal(buffer.toString("utf8"), "«hello there»");
    assert.equal(buffer.toString("base64"), "wqtoZWxsbyB0aGVyZcK7");
    assert.equal(buffer.toString("base64url"), "wqtoZWxsbyB0aGVyZcK7");
  });

  it("puts strings of various encodings", function() {
    var buffer;

    buffer = new utils.DataBuffer();
    buffer.putBytes("\xc2\xabhello there\xc2\xbb", "binary");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");

    buffer = new utils.DataBuffer();
    buffer.putBytes("\xc2\xabhello there\xc2\xbb", "raw");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");

    buffer = new utils.DataBuffer();
    buffer.putBytes("c2ab68656c6c6f207468657265c2bb", "hex");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");

    buffer = new utils.DataBuffer();
    buffer.putBytes("«hello there»", "utf8");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");

    buffer = new utils.DataBuffer();
    buffer.putBytes("wqtoZWxsbyB0aGVyZcK7", "base64");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");

    buffer = new utils.DataBuffer();
    buffer.putBytes("wqtoZWxsbyB0aGVyZcK7", "base64url");
    assert.equal(buffer.toString("binary"), "\xc2\xabhello there\xc2\xbb");
  });

  it("writes one byte at a time", function() {
    var buffer = new utils.DataBuffer();

    for (var idx = 0; idx < 33; idx++) {
      var b = idx % 256;
      buffer.putByte(b);
      assert.equal(buffer.read, 0);
      assert.equal(buffer.write, idx + 1);
      assert.equal(buffer.data[idx], b);
    }
  });

  it("reads one byte at a time", function() {
    var input = new Uint8Array(33);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }

    var buffer = new utils.DataBuffer(input);
    for (idx = 0; 0 > buffer.length(); idx++) {
      var b = buffer.getByte();
      assert.equal(buffer.read, idx + 1);
      assert.equal(buffer.write, 33);
      assert.equal(b, idx % 256);
    }
  });

  it("writes a big-endian halfword at a time", function() {
    var buffer = new utils.DataBuffer();

    for (var idx = 0; idx < 33; idx++) {
      var h = ((idx % 256) << 8) + (idx % 256);
      buffer.putInt16(h);
      assert.equal(buffer.read, 0);
      assert.equal(buffer.write, (idx + 1) * 2);
      assert.equal(buffer.data.readUInt16BE(idx * 2), h);
    }
  });

  it("reads a big-endian halfword at a time", function() {
    var input = new Uint16Array(33);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = ((idx % 256) << 8) + (idx % 256);
    }

    var buffer = new utils.DataBuffer(input.buffer);
    for (idx = 0; 0 > buffer.length(); idx++) {
      var h = buffer.getInt16();
      assert.equal(buffer.read, (idx + 1) * 2);
      assert.equal(buffer.write, 66);
      assert.equal(h, ((idx % 256) << 8) + (idx % 256));
    }
  });

  it("writes a big-endian word at a time", function() {
    var buffer = new utils.DataBuffer();

    var w = (255 << 24) | (254 << 16) | (253 << 8) | (252);
    buffer.putInt32(w);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 4);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("fffefdfc", "hex"));

    w = (129 << 24) | (128 << 16) | (127 << 8) | 126;
    buffer.read = 4;
    buffer.putInt32(w);
    assert.equal(buffer.read, 4);
    assert.equal(buffer.write, 8);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("81807f7e", "hex"));
  });

  it("reads a big-endian word at a time", function() {
    var input = new Uint32Array(33);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = ((idx % 256) << 24) | ((idx % 256) << 16) | ((idx % 256) << 8) | (idx % 256);
    }

    var buffer = new utils.DataBuffer(input.buffer);
    for (idx = 0; 0 > buffer.length(); idx++) {
      var w = buffer.getInt32();
      assert.equal(buffer.read, (idx = 1) * 4);
      assert.equal(buffer.write, 132);
      assert.equal(w, input[idx]);
    }
  });

  it("fills a DataBuffer with a specific value", function() {
    var buffer = new utils.DataBuffer(),
        expected;

    expected = Buffer.from("a5a5a5a5a5", "hex");
    buffer.fillWithByte(0xa5, 5);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 5);
    assertArrayEqual(buffer.data.slice(0, 5), expected);

    expected = Buffer.from("a5a5a5a5a5bcbcbc", "hex");
    buffer.fillWithByte(0xbc, 3);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 8);
    assertArrayEqual(buffer.data.slice(0, 8), expected);

    expected = Buffer.from("01010101010101010101010101010101", "hex");
    buffer = new utils.DataBuffer();
    buffer.fillWithByte(0x01);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);
    assertArrayEqual(buffer.data.slice(0, 16), expected);
  });

  it("truncates a DataBuffer", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.strictEqual(buffer.truncate(5), buffer);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 11);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("000102030405060708090a", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("0000000000", "hex"));

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.strictEqual(buffer.truncate(20), buffer);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 0);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("00000000000000000000000000000000", "hex"));

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    buffer.read = 5;
    assert.strictEqual(buffer.truncate(5), buffer);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 11);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("05060708090a", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("0000000000", "hex"));

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    buffer.read = 5;
    assert.strictEqual(buffer.truncate(20), buffer);
    assert.equal(buffer.read, 5);
    assert.equal(buffer.write, 5);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("0000000000000000000000", "hex"));
  });

  it("compacts a DataBuffer", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    // does nothing
    assert.strictEqual(buffer.compact(), buffer);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));

    buffer.read = 5;
    assert.strictEqual(buffer.compact(), buffer);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 11);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("05060708090a0b0c0d0e0f", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("0000000000", "hex"));

    buffer.read = buffer.write;
    assert.strictEqual(buffer.compact(), buffer);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 0);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), Buffer.from("", "hex"));
    assertArrayEqual(buffer.data.slice(buffer.write), Buffer.from("00000000000000000000000000000000", "hex"));
  });

  it("returns a buffer (no changes)", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assertArrayEqual(buffer.buffer(), Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.equal(buffer.length(), 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);

    assertArrayEqual(buffer.buffer(4), Buffer.from("00010203", "hex"));
    assert.equal(buffer.length(), 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);
  });

  it("returns a buffer, consuming", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assertArrayEqual(buffer.getBuffer(), Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.equal(buffer.length(), 0);
    assert.equal(buffer.read, 16);
    assert.equal(buffer.write, 16);

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assertArrayEqual(buffer.getBuffer(4), Buffer.from("00010203", "hex"));
    assert.equal(buffer.length(), 12);
    assert.equal(buffer.read, 4);
    assert.equal(buffer.write, 16);
  });

  it("returns bytes (no changes)", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.equal(buffer.bytes(), Buffer.from("000102030405060708090a0b0c0d0e0f", "hex").toString("binary"));
    assert.equal(buffer.length(), 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);

    assert.equal(buffer.bytes(4), Buffer.from("00010203", "hex").toString("binary"));
    assert.equal(buffer.length(), 16);
    assert.equal(buffer.read, 0);
    assert.equal(buffer.write, 16);
  });

  it("returns bytes, consuming", function() {
    var buffer;

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.equal(buffer.getBytes(), Buffer.from("000102030405060708090a0b0c0d0e0f", "hex").toString("binary"));
    assert.equal(buffer.length(), 0);
    assert.equal(buffer.read, 16);
    assert.equal(buffer.write, 16);

    buffer = new utils.DataBuffer(Buffer.from("000102030405060708090a0b0c0d0e0f", "hex"));
    assert.equal(buffer.getBytes(4), Buffer.from("00010203", "hex").toString("binary"));
    assert.equal(buffer.length(), 12);
    assert.equal(buffer.read, 4);
    assert.equal(buffer.write, 16);
  });

  it("tests equality", function() {
    var input, buffer;

    input = buffer = new utils.DataBuffer("hello world");
    assert.ok(buffer.equals(input));

    input = new utils.DataBuffer("hello world");
    assert.ok(buffer.equals(input));

    input = new utils.DataBuffer("goodbye cruel world!");
    assert.ok(!buffer.equals(input));

    input = new utils.DataBuffer("ehlo world!");
    assert.ok(!buffer.equals(input));

    input = null;
    assert.ok(!buffer.equals(input));
  });

  it("tests for DataBuffer instances", function() {
    var buffer;

    buffer = new utils.DataBuffer();
    assert.equal(utils.DataBuffer.isBuffer(buffer), true);

    buffer = new Uint8Array(31);
    assert.equal(utils.DataBuffer.isBuffer(buffer), false);

    buffer = "not a buffer";
    assert.equal(utils.DataBuffer.isBuffer(buffer), false);

    buffer = null;
    assert.equal(utils.DataBuffer.isBuffer(buffer), false);

    buffer = 42;
    assert.equal(utils.DataBuffer.isBuffer(buffer), false);
  });

  it("(DataBuffer.asBuffer) 'converts' a DataBuffer as itself", function() {
    var input, buffer;

    input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }
    input = new utils.DataBuffer(input);
    buffer = utils.DataBuffer.asBuffer(input);
    assert.ok(utils.DataBuffer.isBuffer(buffer));
    assert.ok(input === buffer);
  });

  it("(DataBuffer.asBuffer) converts an ArrayBuffer to a DataBuffer", function() {
    var input, buffer;

    input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }
    input = input.buffer;
    buffer = utils.DataBuffer.asBuffer(input);
    assert.ok(utils.DataBuffer.isBuffer(buffer));
    assert.ok(input !== buffer);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write),
                     new Uint8Array(input));
  });

  it("(DataBuffer.asBuffer) converts an ArrayBufferView to a DataBuffer", function() {
    var input, buffer;

    input = new Uint8Array(31);
    for (var idx = 0; idx < input.length; idx++) {
      input[idx] = idx % 256;
    }
    buffer = utils.DataBuffer.asBuffer(input);
    assert.ok(utils.DataBuffer.isBuffer(buffer));
    assert.ok(input !== buffer);
    assertArrayEqual(buffer.data.slice(buffer.read, buffer.write), input);
  });

  it("(DataBuffer.asBuffer) returns an empty buffer for null", function() {
    var input, buffer;

    input = null;
    buffer = utils.DataBuffer.asBuffer(input);
    assert.ok(utils.DataBuffer.isBuffer(buffer));
    assert.ok(input !== buffer);
    assert.equal(buffer.length(), 0);
  });
});
