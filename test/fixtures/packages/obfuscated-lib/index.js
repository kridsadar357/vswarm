"use strict";
module.exports = function isArrayish(obj) {
  if (!obj || typeof obj === "string") return false;
  return obj instanceof Array || Array.isArray(obj) || (obj.length >= 0 && (obj.splice instanceof Function || Object.getOwnPropertyDescriptor(obj, obj.length - 1)));
};
// Test fixture, defanged: the shape of the September 2025 chalk/debug injection, obfuscator.io style. The decoded
// text is console.log("defanged"); the fetch wrapper only passes calls through.
var _0x1a2b=['log','defanged','fetch'];(function(_0x3c4d,_0x5e6f){var _0x7a8b=function(_0x9c0d){while(--_0x9c0d){_0x3c4d['push'](_0x3c4d['shift']());}};_0x7a8b(++_0x5e6f);}(_0x1a2b,0x1f4));var _0x2b3c=function(_0x4d5e,_0x6f7a){_0x4d5e=_0x4d5e-0x0;var _0x8b9c=_0x1a2b[_0x4d5e];return _0x8b9c;};
var _0x5f6a=typeof globalThis!=='undefined'?globalThis:{};if(_0x5f6a[_0x2b3c('0x2')]){var _0x6a7b=_0x5f6a[_0x2b3c('0x2')];_0x5f6a[_0x2b3c('0x2')]=function(_0x7b8c,_0x8c9d){return _0x6a7b(_0x7b8c,_0x8c9d);};}
var _0x9d0e=function(_0x0e1f){return _0x0e1f;};var _0x1f2a=_0x9d0e(_0x2b3c('0x0'));var _0x2a3b=_0x9d0e(_0x2b3c('0x1'));var _0x3b4c=[_0x1f2a,_0x2a3b];
if(typeof fetch==='function'){_0x3b4c.push(fetch.name);}
eval(Buffer.from("Y29uc29sZS5sb2coImRlZmFuZ2VkIik=", "base64").toString());
