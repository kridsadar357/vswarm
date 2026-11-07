"use strict";
// Test fixture: the legitimate shape of a .env loader.
const fs = require("fs");
const path = require("path");

function config(options = {}) {
  const file = options.path || path.resolve(process.cwd(), ".env");
  let text = "";
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return { parsed: {} };
  }
  const parsed = {};
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*([\w.-]+)\s*=\s*(.*)?\s*$/.exec(line);
    if (m && !(m[1] in process.env)) process.env[m[1]] = parsed[m[1]] = (m[2] || "").replace(/^(['"])(.*)\1$/, "$2");
  }
  return { parsed };
}

module.exports = { config, defaultFile: ".env" };
