const isNumber = require("is-number");
module.exports = (xs) => xs.filter(isNumber).reduce((a, b) => a + Number(b), 0);
