'use strict';
const commander = require('commander');
const fs = require('fs');
const version = require('../package.json').version;
const params = require('./utils/params');
const constants = require('./utils/constants');

const jose = require('../lib');

const SERIALIZATION = constants.SERIALIZATION;

commander
    .version(version)

commander
    .arguments('[signature]')
    .option('--key <file>', 'path to key or certificate', params.file(commander, 'key'))
    .option('--key-format <format>', 'key format, one of "json","private","pkcs8","public","spki","pkix","x509","pem" (default)', params.choice(commander, 'key-format', ["json","private","pkcs8","public","spki","pkix","x509","pem"]), "pem")
    .option('--serialization <format>', 'signature encoding, one of "compact","flattened","general" (default)', params.choice(commander, 'key-format', ["compact","flattened","general"]), "general")
    .option('--signature <file>', 'path to signature, ignored if [signature] specified', params.file(commander, 'signature'))
    .action(function(signature, options, cmd) {
        let exit;
        let sign;

        if (!signature && !options.signature) {
            console.log('--signature parameter or [signature] argument is required');
            exit = true;
        } else {
            if (SERIALIZATION.COMPACT === options.format) {
                sign = (signature || options.signature).toString('utf-8');
            } else {
                sign = JSON.parse((signature || options.signature).toString('utf-8'));
            }
        }

        if (exit) {
            process.exit(1);
        }

        jose.JWS.createVerify()
            .verify(sign)
            .then(console.log)
            .catch(console.log)
    })

commander
    .parse(process.argv)

if (!process.argv.slice(2).length) {
    commander.outputHelp();
}
