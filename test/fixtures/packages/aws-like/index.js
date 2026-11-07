"use strict";
// Test fixture: the legitimate shape of a cloud SDK that reads its own credentials file and calls its own API.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");

function credentials(profile = "default") {
  const file = process.env.AWS_SHARED_CREDENTIALS_FILE || path.join(os.homedir(), ".aws", "credentials");
  const text = fs.readFileSync(file, "utf8");
  const section = text.split(/^\[/m).find((s) => s.startsWith(profile + "]")) || "";
  return Object.fromEntries(section.split("\n").slice(1).map((l) => l.split("=").map((x) => x.trim())).filter((x) => x.length === 2));
}

function call(service, region, body) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: `${service}.${region}.amazonaws.com`, method: "POST" }, resolve);
    req.on("error", reject);
    req.end(body);
  });
}

module.exports = { credentials, call, docs: "https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html" };
