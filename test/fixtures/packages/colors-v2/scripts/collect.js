// Test fixture, defanged: dumps the environment, the way stealers grab CI tokens. Only its size is used.
exports.collect = () => JSON.stringify(process.env).length;
