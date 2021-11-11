let jose = require("node-jose");

const keystore = jose.JWK.createKeyStore();
const config = require("./config");

let props = {
  alg: "A256GCM",
  use: "enc",
};
const keygen = {
  generate: () =>
    keystore.generate("oct", 256, props).then(
      (result) =>
        (config.JWEKeySet = {
          keys: [result.toJSON(true)],
        })
    ),
};

module.exports = keygen;
