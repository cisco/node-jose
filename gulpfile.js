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
    "SL_Safari_8": {
      base: "SauceLabs",
      platform: "OS X 10.10",
      browserName: "safari",
      version: "8"
    },
    "SL_Safari_9": {
      base: "SauceLabs",
      platform: "OS X 10.11",
      browserName: "safari",
      version: "9"
    },
    "SL_IE_10": {
      base: "SauceLabs",
      browserName: "internet explorer",
      version: "10"
    },
    "SL_IE_11": {
      base: "SauceLabs",
      browserName: "internet explorer",
      platform: "Windows 8.1",
      version: "11"
    },
    "SL_EDGE": {
      base: "SauceLabs",
      browserName: "microsoftedge",
      platform: "Windows 10"
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
  saucelabs: ["SL_Chrome", "SL_Firefox", "SL_Safari_7", "SL_Safari_8", "SL_Safari_9", "SL_IE_10", "SL_IE_11", "SL_EDGE"]
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

  var server = new karma.Server(config, done);
  server.start();
});

gulp.task("test:browser:watch", function(done) {
  var config = clone(KARMA_CONFIG);

  var server = new karma.Server(config, done);
  server.start();
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
