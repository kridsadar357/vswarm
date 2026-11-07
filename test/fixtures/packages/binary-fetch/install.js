// Test fixture: the legitimate shape of a package that downloads its prebuilt binary at install (esbuild, prisma,
// sentry-cli) and checks that it runs. Never run by the tests.
"use strict";
const fs = require("fs");
const https = require("https");
const path = require("path");
const child_process = require("child_process");

const version = require("./package.json").version;
const url = `https://github.com/example/fast-bundler/releases/download/v${version}/fast-bundler-${process.platform}-${process.arch}`;
const dest = path.join(__dirname, "bin", "fast-bundler");

function fetch(u) {
  return new Promise((resolve, reject) => {
    https.get(u, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) return fetch(res.headers.location).then(resolve, reject);
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve(Buffer.concat(chunks)));
    }).on("error", reject);
  });
}

fetch(url).then((buf) => {
  fs.writeFileSync(dest, buf);
  fs.chmodSync(dest, 0o755);
  child_process.execFileSync(dest, ["--version"], { stdio: "ignore" });
}).catch(() => process.exit(0));
