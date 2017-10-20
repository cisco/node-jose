'use strict';
const commander = require('commander');
const childProcess = require('child_process');
const version = require('../package.json').version;

const jose = require('../lib');

commander
    .version(version)

commander
    .command('jws <command>', 'jws toolset for signature operations')

commander
    .parse(process.argv)

if (!process.argv.slice(2).length) {
    command.outputHelp();
}
