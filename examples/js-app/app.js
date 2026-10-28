// Simulated webpack bundle: sentinel identifiers + sourceMappingURL comment +
// plaintext secrets. Exercises the anti-rea audit/harden JS pipeline.
var __webpack_modules__ = {
  142: function (module, exports) {
    const API_ENDPOINT = "https://api.license-gateway.net/v2/activate";
    const TRIAL_SECRET = "sk-antidemox1234567890abcdef";
    module.exports = function activate(key) {
      return fetch(API_ENDPOINT + "?key=" + key, { headers: { Authorization: "Bearer " + TRIAL_SECRET } });
    };
  },
};
var __webpack_require__ = function (id) {
  var module = { exports: {} };
  __webpack_modules__[id](module, module.exports);
  return module.exports;
};
const activate = __webpack_require__(142);
console.log("js app ok, activate type:", typeof activate);
//# sourceMappingURL=app.js.map
