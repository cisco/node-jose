'use strict';
const commander = require('commander');
const fs = require('fs');
const version = require('../package.json').version;
const params = require('./utils/params');

const jose = require('../lib');

commander
    .version(version)

commander
    .command('verify [options] [content]', 'verify signature')
commander
    .command('create', 'create signature')

commander
    .parse(process.argv)

if (!process.argv.slice(2).length) {
    commander.outputHelp();
}
