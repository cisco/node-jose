/*!
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var assert = require("chai").assert;

const CURVES = require('../../lib/deps/ecc/curves.js');
const BigInteger = require('../../lib/deps/forge').jsbn.BigInteger;

describe("ecc/positive", function() {
  const negativeModInverseCases = [
    '101067240514044546216936289506154965497874315269115226505131909313278720169941',
    '47260992668897782856940293132731814279826643476197468731642996160637470667669',
  ]
  
  const p = CURVES["P-256"].curve.p;

  const runner = () => {
    for (const kStr of negativeModInverseCases) {
      const k = new BigInteger(kStr);
      const kinv = k.modInverse(p);
      assert.isAtLeast(kinv.s, 0, "Negative mod inverse");
    }
  };

  it('normalizes negative modular inverses', runner);
})
