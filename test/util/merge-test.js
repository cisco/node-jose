/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var chai = require("chai");
var assert = chai.assert;

var utils = {
  merge: require("../../lib/util/merge")
};

describe("util/merge", function() {
  it("maintains node.js Buffer", function() {
    var expected = {
      foo: "bar",
      bar: Buffer.from([0x62, 0x61, 0x7a]),
      baz: 42
    };
    var actual = {
      foo: "bar"
    };
    actual = utils.merge(actual, {
      baz: 42,
      bar: Buffer.from([0x62, 0x61, 0x7a])
    });
    assert.deepEqual(actual, expected);
    assert.ok(Buffer.isBuffer(actual.bar));
  });
  it("maintains Uint8Array Buffer", function() {
    var expected = {
      foo: "bar",
      bar: new Uint8Array([0x62, 0x61, 0x7a]),
      baz: 42
    };
    var actual = {
      foo: "bar"
    };
    actual = utils.merge(actual, {
      baz: 42,
      bar: new Uint8Array([0x62, 0x61, 0x7a])
    });
    assert.deepEqual(actual, expected);
    assert.ok(actual.bar instanceof Uint8Array);
  });
  if ("undefined" !== typeof Uint8ClampedArray) {
    it("maintains Uint8ClampedArray Buffer", function() {
      var expected = {
        foo: "bar",
        bar: new Uint8ClampedArray([0x62, 0x61, 0x7a]),
        baz: 42
      };
      var actual = {
        foo: "bar"
      };
      actual = utils.merge(actual, {
        baz: 42,
        bar: new Uint8ClampedArray([0x62, 0x61, 0x7a])
      });
      assert.deepEqual(actual, expected);
      assert.ok(actual.bar instanceof Uint8ClampedArray);
    });
  }
  it("maintains Uint16Array Buffer", function() {
    var expected = {
      foo: "bar",
      bar: new Uint16Array([0x62, 0x61, 0x7a]),
      baz: 42
    };
    var actual = {
      foo: "bar"
    };
    actual = utils.merge(actual, {
      baz: 42,
      bar: new Uint16Array([0x62, 0x61, 0x7a])
    });
    assert.deepEqual(actual, expected);
    assert.ok(actual.bar instanceof Uint16Array);
  });
  it("maintains Uint32Array Buffer", function() {
    var expected = {
      foo: "bar",
      bar: new Uint32Array([0x62, 0x61, 0x7a]),
      baz: 42
    };
    var actual = {
      foo: "bar"
    };
    actual = utils.merge(actual, {
      baz: 42,
      bar: new Uint32Array([0x62, 0x61, 0x7a])
    });
    assert.deepEqual(actual, expected);
    assert.ok(actual.bar instanceof Uint32Array);
  });
});
