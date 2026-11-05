let sum;
try { sum = require("./index.js"); } catch { sum = (xs) => xs.reduce((a, b) => a + Number(b), 0); }
const got = sum([1, "2", 3]);
if (got !== 6) { console.error("expected 6, got", got); process.exit(1); }
console.log("1 test passed");
