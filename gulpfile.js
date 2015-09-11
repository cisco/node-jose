/**
 * gulpfile.js - Gulp-based build
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var ARGV = require("yargs").
    usage("$0 [options] task [task ...]").
    option("browsers", {
      type: "string",
      describe: "browsers to run tests in",
      default: ""
    }).
    option("sauce", {
      type: "boolean",
      describe: "use SauceLabs for tests/reporting",
      default: false
    }).
    help("help").
    argv;

var browserify = require("browserify"),
    clone = require("lodash.clone"),
    gulp = require("gulp"),
    karma = require("karma"),
    merge = require("lodash.merge"),
    mocha = require("gulp-mocha"),
    istanbul = require("gulp-istanbul"),
    del = require("del"),
    runSequence = require("run-sequence");

// ### 'CONSTANTS' ###
var SOURCES = ["./lib/**/*.js", "!(./lib/old/**/*.js)"],
    TESTS = "./test/**/*-test.js";

// ### HELPERS ###
var MOCHA_CONFIG = {
  timeout: 600000
};

// ### LINT TASKS ###
function doEslint() {
  var eslint = require("gulp-eslint");

  return gulp.src([
    "lib/**/*.js",
    "test/**/*.js",
    "gulpfile.js"
  ])
    .pipe(eslint())
    .pipe(eslint.format());
}

gulp.task("eslint", function() {
  return doEslint();
});

gulp.task("test:lint", function() {
  var eslint = require("gulp-eslint");
  return doEslint()
    .pipe(eslint.failOnError());
});

// ### CLEAN TASKS ###
gulp.task("clean:coverage:nodejs", function() {
  del("coverage/nodejs");
});
gulp.task("clean:coverage:browser", function() {
  del("coverage/browser");
});
gulp.task("clean:coverage", function() {
  del("coverage");
});

gulp.task("clean:dist", function() {
  del("dist");
});

// ### NODEJS TASKS ###
function doTestsNodejs() {
  return gulp.src(TESTS).
              pipe(mocha(MOCHA_CONFIG));
}

gulp.task("test:nodejs:single", function() {
  return doTestsNodejs();
});

gulp.task("cover:nodejs", function() {
  return gulp.src(SOURCES).
              pipe(istanbul()).
              pipe(istanbul.hookRequire()).
              on("finish", function() {
                doTestsNodejs().
                pipe(istanbul.writeReports({
                  dir: "./coverage/nodejs",
                  reporters: ["html", "text-summary"]
                }));
              });
});

gulp.task("test:nodejs", function(cb) {
  runSequence("test:lint",
              "test:nodejs:single",
              cb);
});

// ### BROWSER TASKS ###
function doBrowserify(suffix, steps) {
  var source = require("vinyl-source-stream"),
      buffer = require("vinyl-buffer"),
      sourcemaps = require("gulp-sourcemaps");

  var pkg = require("./package.json");

  suffix = suffix || ".js";
  steps = steps || [];

  var stream = browserify({
    entries: require("path").resolve(pkg.main),
    standalone: "jose"
  }).bundle().
  pipe(source(pkg.name + suffix)).
  pipe(buffer());

  steps.forEach(function(s) {
    stream = stream.pipe(s);
  });

  return stream.pipe(sourcemaps.init({ loadMaps: true })).
                pipe(sourcemaps.write("./")).
                pipe(gulp.dest("./dist"));
}

gulp.task("bundle", function() {
  return doBrowserify();
});

gulp.task("minify", function() {
  var uglify = require("gulp-uglify");

  return doBrowserify(".min.js", [
    uglify()
  ]);
});

var KARMA_CONFIG = {
  frameworks: ["mocha", "browserify"],
  basePath: ".",
  browserDisconnectTolerance: 1,
  browserDisconnectTimeout: 600000,
  browserNoActivityTimeout: 600000,
  client: {
    mocha: MOCHA_CONFIG
  },
  preprocessors: {
    "test/**/*-test.js": ["browserify"]
  },
  reporters: ["mocha"],
  browserify: {
    debug: true
  },
  customLaunchers: {
    "SL_Chrome": {
      base: "SauceLabs",
      browserName: "chrome"
    },
    "SL_Firefox": {
      base: "SauceLabs",
      browserName: "firefox"
    },
    "SL_Safari": {
      base: "SauceLabs",
      platform: "OS X 10.9",
      browserName: "safari",
      version: "7"
    },
    "SL_IE": {
      base: "SauceLabs",
      browserName: "internet explorer",
      version: "10"
    }
  },
  captureTimeout: 600000,
  sauceLabs: {
    testName: "node-jose",
    commandTimeout: 300
  },
  files: [TESTS]
};
var KARMA_BROWSERS = {
  local: ["Chrome", "Firefox"],
  saucelabs: ["SL_Chrome", "SL_Firefox", "SL_IE", "SL_Safari"]
};
// allow for IE on windows
if (/^win/.test(process.platform)) {
  KARMA_BROWSERS.local.push("IE");
}
// allow for Safari on Mac OS X
if (/^darwin/.test(process.platform)) {
  KARMA_BROWSERS.local.push("Safari");
}

gulp.task("test:browser:single", function(done) {
  var browsers = ARGV.browsers.split(/\s*,\s*/g).
                 filter(function (v) { return v; });

  var config = merge({}, KARMA_CONFIG, {
    singleRun: true
  });
  if (ARGV.sauce) {
    config = merge(config, {
      reporters: ["mocha", "saucelabs"],
      browsers: KARMA_BROWSERS.saucelabs
    });
  } else {
    config.browsers = KARMA_BROWSERS.local;
  }
  if (browsers.length) {
    config.browsers = config.browsers.filter(function(b) {
      b = b.replace("SL_", "");
      return -1 !== browsers.indexOf(b);
    });
  }

  karma.server.start(config, done);
});

gulp.task("test:browser:watch", function(done) {
  var config = clone(KARMA_CONFIG);

  karma.server.start(config, done);
});

gulp.task("test:browser", function(cb) {
  runSequence("test:lint",
              "test:browser:single",
              cb);
});

// ### MAIN TASKS ###
gulp.task("test", function(cb) {
  runSequence("test:lint",
              "test:browser:single",
              "test:nodejs:single",
              cb);
});
gulp.task("coverage", function(cb) {
  runSequence("test:lint",
              "cover:nodejs",
              cb);
});
gulp.task("clean", ["clean:coverage", "clean:dist"]);
gulp.task("dist", function(cb) {
  runSequence("clean:dist",
              "test:lint",
              "test:browser",
              ["bundle", "minify"],
              cb);
});

// ### MAIN WATCHERS ###
gulp.task("watch:test", ["test"], function() {
  return gulp.watch([SOURCES, TESTS], ["test:nodejs", "test:browser"]);
});

// ### DEFAULT ###
gulp.task("default", ["test"]);
