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
          // keys: [result.toJSON(true)],
          keys: [
            {
              kty: "oct",
              kid: "if9hARwTJbgfBwLWcefcg2d3TKo_gqUlWp72th9q3vo",
              use: "enc",
              alg: "A256GCM",
              k: "saC97DZg4M25dDjTQKXqgFVOTy0iOK8AxNQsn6-MRSE",
            },
          ],
        })
    ),
};

module.exports = keygen;
