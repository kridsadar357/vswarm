"use strict";
// A tiny colour helper: the clean version of the fixture.
const wrap = (open, close) => (s) => `\u001b[${open}m${s}\u001b[${close}m`;
module.exports = {
  red: wrap(31, 39),
  green: wrap(32, 39),
  bold: wrap(1, 22),
};
