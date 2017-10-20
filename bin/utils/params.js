'use strict';
const fs = require('fs')
const path = require('path')

/**
 * Reads file parameter and outputs error if file is not available
 *
 * @param {npm.commander} commander commander instance
 * @param {String} param param name used in error messages
 * @param {String} file file name
 * @returns {Buffer} file contents
 */
function fileParam(commander, param, file) {
    try {
        return fs.readFileSync(file);
    } catch (ex) {
        console.log(`Error: ${param} file "${file}" is not found\n`);
        commander.outputHelp();
        process.exit(1);
    }
}

/**
 * Reads file parameter and checks whether file is accessible for write
 *
 * @param {npm.commander} commander commander instance
 * @param {String} param param name used in error messages
 * @param {String} file file name
 * @returns {Buffer} file contents
 */
function targetFileParam(commander, param, file) {
    try {
        if (fs.existsSync(file)) {
            console.log(`Error: ${param} file "${file}" is already exists\n`);
            commander.outputHelp();
            process.exit(1);
        }
        fs.accessSync(path.dirname(file), fs.constants.W_OK);
        return file;
    } catch (ex) {
        if ('EACCES' === ex.code) {
            console.log(`Error: ${param} file "${file}" access denied\n`);
        } else if ('ENOENT' === ex.code) {
            console.log(`Error: ${param} file "${file}" does not exists\n`);
        } else {
            console.log(`Error: ${param} file "${file}" access unexpected problem\n`);
        }
        process.exit(1);
    }
}


/**
 * Reads file parameter and outputs error if file is not available
 *
 * @param {npm.commander} commander commander instance
 * @param {String} param param name used in error messages
 * @param {String} value param value
 * @returns {String} value
 */
function choiceParam(commander, param, choice, value='', def) {
    const val = (value || def).toLowerCase();
    const idx = choice.indexOf(val);

    if (idx < 0) {
        console.log(`Error: ${param} value "${value}" is not valid, choose one of "${choice.join('", "')}"`);
        process.exit(1);
    } else {
        return val;
    }
}

module.exports.file = (commander, param)=>fileParam.bind(null, commander, param);
module.exports.targetfile = (commander, param)=>targetFileParam.bind(null, commander, param);
module.exports.choice = (commander, param, choice)=>choiceParam.bind(null, commander, param, choice);