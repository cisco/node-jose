/*!
 * icon/index.js - ICON PDS Client
 */
"use strict";

var pdsClient = {
    serverCheck: require("./pds_client").server_check,
    validation: require("./pds_client").validation
};

module.exports = pdsClient;
