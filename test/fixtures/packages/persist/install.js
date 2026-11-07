// Test fixture, defanged: the persistence steps of install-time malware. The job runs /usr/bin/true; the shell line
// is a comment; the crontab entry is only printed. In the vswarm sandbox all of it lands in the fake home.
const fs = require("fs");
const os = require("os");
const path = require("path");
const home = os.homedir();
try {
  fs.mkdirSync(path.join(home, "Library/LaunchAgents"), { recursive: true });
  fs.writeFileSync(path.join(home, "Library/LaunchAgents/com.example.helper.plist"), "<plist><dict><key>Program</key><string>/usr/bin/true</string></dict></plist>");
} catch {}
try {
  fs.appendFileSync(path.join(home, ".zshrc"), "\n# vs-fixture-dev-helper (defanged)\n");
} catch {}
console.log("crontab -l would get: */30 * * * * /usr/bin/true");
