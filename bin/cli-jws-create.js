'use strict';
const commander = require('commander');
const fs = require('fs');
const version = require('../package.json').version;
const params = require('./utils/params');
const constants = require('./utils/constants');

const jose = require('../lib');

const SERIALIZATION = constants.SERIALIZATION;
const EMBED = constants.EMBED;

commander
    .version(version)

commander
    .arguments('[content]')
    .option('--certificate <file>', 'path to certificate', params.file(commander, 'certificate'))
    .option('--key <file>', 'path to private key', params.file(commander, 'key'))
    .option('--key-format <format>', 'key format, one of "json","private","pkcs8","public","spki","pkix","x509","pem" (default)', params.choice(commander, 'key-format', ["json","private","pkcs8","public","spki","pkix","x509","pem"]), "pem")
    .option('--serialization <format>', 'signature encoding, one of "compact", "flattened", "general" (default)', params.choice(commander, 'serialization', Object.values(SERIALIZATION)), SERIALIZATION.GENERAL)
    .option('--embed <format>', 'add key to a signature, one of "x5c", "jwk" (default)', params.choice(commander, 'embed', Object.values(EMBED)))
    .option('--in <file>', 'path to content, ignored if argument is passed', params.file(commander, 'in'))
    .option('--out <file>', 'path to signature', params.targetfile(commander, 'out'))
    .action((content, options, cmd) => {
        const sigData = {
            format: options.serialization
        };
        const sigOpts = {
        };

        let exit;
        let key, cert;

        if (!options.key) {
            console.log('--key is required');
            exit = true;
        } else {
            key = options.key.toString('utf-8')
        }

        if (!options.certificate) {
            console.log('--certificate is required');
            exit = true;
        } else {
            cert = options.certificate.toString('utf-8').replace(/-.+-/g,'').replace(/\s/g,'');
        }


        if (!content && !options.in) {
            console.log('--in parameter or [content] argument is required');
            exit = true;
        }

        if (options.embed) {
            sigOpts.reference = options.embed;
            if (!sigOpts.header) {
                sigOpts.header = {};
            }
            sigOpts.header[options.embed] = [].concat(cert);
        }

        if (exit) {
            process.exit(1);
        }

        jose.JWK.asKey(key, "pem")
            .then(jwk => jose.JWS.createSign(sigData, Object.assign({}, sigOpts, { key: jwk })))
            .then(jws => jws.update(content || options.in.toString('utf-8')).final())
            .then(data => {
                if (options.out) {
                    fs.writeFileSync(options.out, JSON.stringify(data));
                } else {
                    console.log(JSON.stringify(data));
                }
            });
    })

commander
    .parse(process.argv)

if (!process.argv.slice(2).length) {
    commander.outputHelp();
}
