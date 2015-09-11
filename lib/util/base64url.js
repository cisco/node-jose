/*!
 * util/base64url.js - Implementation of web-safe Base64 Encoder/Decoder
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

/**
 * @namespace base64url
 * @description
 * Provides methods to encode and decode data according to the
 * base64url alphabet.
 */
var base64url = exports;
/**
 * Encodes the input to base64url.
 *
 * If {input} is a Buffer, then {encoding} is ignored. Otherwise,
 * {encoding} can be one of "binary", "base64", "hex", "utf8".
 *
 * @param {Buffer|String} input The data to encode.
 * @param {String} [encoding = binary] The input encoding format.
 * @returns {String} the base64url encoding of {input}.
 */
base64url.encode = function(input, encoding) {
  var fn = function(match) {
    switch(match) {
      case "+": return "-";
      case "/": return "_";
      case "=": return "";
    }
    // should never happen
  };

  encoding = encoding || "binary";
  if (Buffer.isBuffer(input)) {
    input = input.toString("base64");
  } else {
    if ("undefined" !== typeof ArrayBuffer && input instanceof ArrayBuffer) {
      input = new Uint8Array(input);
    }
    input = new Buffer(input, encoding).toString("base64");
  }

  return input.replace(/\+|\/|\=/g, fn);
};
/**
 * Decodes the input from base64url.
 *
 * If {encoding} is not specified, then this method returns a Buffer.
 * Othewise, {encoding} can be one of "binary", "base64", "hex", "utf8";
 * this method then returns a string matching the given encoding.
 *
 * @param {String} input The data to decode.
 * @param {String} [encoding] The output encoding format.
 * @returns {Buffer|String} the base64url decoding of {input}.
 */
base64url.decode = function(input, encoding) {
  var fn = function(match) {
    switch(match) {
      case "-": return "+";
      case "_": return "/";
    }
    // should never happen
  };

  input = input.replace(/\-|\_/g, fn);
  var output = new Buffer(input, "base64");
  if (encoding) {
    output = output.toString(encoding);
  }
  return output;
};
