/**
 * gulpfile.js - Gulp-based build
 *
 * Copyright (c) 2015 Cisco Systems, Inc. See LICENSE file.
 */
"use strict";

var ARGV = require("yargs").
    usage("$0 [options] task [task ...]").
    option("coverage", {
      type: "boolean",
      describe: "include coverage",
      default: false
    }).
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

var webpack = require("webpack-stream"),
    gulp = require("gulp"),
    merge = require("lodash.merge"),
    mocha = require("gulp-mocha"),
    istanbul = require("gulp-istanbul"),
    del = require("del");

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
  return del("coverage/nodejs");
});
gulp.task("clean:coverage:browser", function() {
  return del("coverage/browser");
});
gulp.task("clean:coverage", function() {
  return del("coverage");
});

gulp.task("clean:dist", function() {
  return del("dist");
});

// ### NODEJS TASKS ###
function doTestsNodejs() {
  return gulp.src(TESTS).pipe(mocha(MOCHA_CONFIG));
}

gulp.task("test:nodejs:single", function() {
  // Constructing the environment descriptor
  var environ = require("util").format(
    "%s %s (%s %s)",
    (process.release && process.release.name) || "node",
    process.version,
    process.platform,
    process.arch
  );
  if (ARGV.coverage) {
    return gulp.src(SOURCES).
                pipe(istanbul()).
                pipe(istanbul.hookRequire()).
                on("finish", function() {
                  doTestsNodejs().
                  pipe(istanbul.writeReports({
                    dir: "./coverage/" + environ,
                    reporters: ["html", "text-summary"]
                  }));
                });
  }
  return doTestsNodejs();
});

gulp.task("test:nodejs", gulp.series("test:lint", "test:nodejs:single"));

// ### BROWSER TASKS ###
gulp.task("bundle", function() {
  var pkg = require("./package.json");

  return gulp.src(require("path").resolve(pkg.main)).
         pipe(webpack({
           mode: "production",
           output: {
             filename: pkg.name + ".min.js"
           },
           devtool: "source-map"
         })).
         pipe(gulp.dest("./dist"));
});

var KARMA_CONFIG = {
  frameworks: ["mocha"],
  concurrency: 1,
  basePath: ".",
  browserDisconnectTolerance: 1,
  browserDisconnectTimeout: 600000,
  browserNoActivityTimeout: 600000,
  client: {
    mocha: MOCHA_CONFIG
  },
  preprocessors: {
    "test/**/*-test.js": ["webpack", "sourcemap"]
  },
  webpack: {
    mode: "development",
    devtool: "inline-source-map"
  },
  webpackMiddleware: {
    noInfo: true
  },
  reporters: ["mocha"],
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
      browserName: "safari"
    },
    "SL_EDGE": {
      base: "SauceLabs",
      browserName: "microsoftedge",
      platform: "Windows 10"
    }
  },
  captureTimeout: 600000,
  sauceLabs: {
    testName: require("./package.json").name,
    commandTimeout: 300
  },
  files: [TESTS]
};
var KARMA_BROWSERS = {
  local: ["Chrome", "Firefox"],
  saucelabs: ["SL_Chrome", "SL_Firefox", "SL_Safari", "SL_EDGE"]
};

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
      b = b.replace("SL_", "").toLowerCase();
      var found = false,
          asked;
      for (var idx = 0; !found && browsers.length > idx; idx++) {
        asked = browsers[idx].toLowerCase();
        found = (0 === b.indexOf(asked));
      }
      return found;
    });
  }
  if (ARGV.coverage) {
    config.browserify.transform = [
      require("browserify-istanbul")({
        ignore: [
          "**/node_modules/**",
          "**/test/**",
          "**/env/**"
        ]
      })
    ];
    config.reporters.push("coverage");
    config.coverageReporter = {
      dir: "./coverage",
      reporters: [
        { type: "html" },
        { type: "text-summary" }
      ]
    };
  }

  var karma = require("karma");
  var server = new karma.Server(config, done);
  server.start();
});

gulp.task("test:browser", gulp.series("test:lint", "test:browser:single"));

// ## TRAVIS-CI TASKS ###
gulp.task("travis:browser", gulp.series(function(cb) {
  if (process.env.SAUCE_USERNAME && process.env.SAUCE_ACCESS_KEY) {
    ARGV.sauce = true;
    merge(KARMA_CONFIG.sauceLabs, {
      startConnect: false,
      tunnelIdentifier: process.env.TRAVIS_JOB_NUMBER || null
    });
  } else {
    ARGV.sauce = false;
    ARGV.browsers="Firefox";
  }
  cb()
}, "test:browser"));

// ### MAIN TASKS ###
gulp.task("test", gulp.series("test:lint", "test:browser:single", "test:nodejs:single"));
gulp.task("clean", gulp.parallel("clean:coverage", "clean:dist"));
gulp.task("dist", gulp.series("clean:dist", "test:lint", "test:browser", "bundle"));

// ### DEFAULT ###
gulp.task("default", gulp.series("test"));
