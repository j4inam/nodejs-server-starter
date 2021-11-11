let jose = require("node-jose");
let config = require("../../config");

const verifyAuthorizationToken = (token) => {
  return new Promise((resolve, reject) => {
    try {
      jose.JWK.asKeyStore(config.JWEKeySet).then((result) => {
        jose.JWE.createDecrypt(result)
          .decrypt(token)
          .then((decodedToken) => {
            console.log("Decoded", decodedToken);
            resolve(JSON.parse(decodedToken.plaintext.toString()));
          })
          .catch((err) => {
            console.log("Decoded err", err);
            reject("Invalid Authorization Bearer! Try Logging-in again!");
          });
      });
    } catch (error) {
      console.log("Some other error", error);
      reject(error);
    }
  });
};

module.exports = {
  authenticate: (req, res, next) => {
    if (req.method == "OPTIONS") res.status(200).send();
    else if (req.headers && req.headers.authorization) {
      const currentTime = (Date.now() / 1000) | 0;
      console.log(currentTime);
      const authorizationToken = req.headers.authorization.replace(
        "Bearer ",
        ""
      );
      verifyAuthorizationToken(authorizationToken)
        .then((user) => {
          console.log("user: ", user);
          if (user._id == undefined || user.email == undefined)
            res.status(401).json({
              msg: "Authentication required",
            });
          else {
            req.user = user;
            console.log("Next post authenticate", req.user);
            if (!next) {
              res.status(200).json(user);
            } else {
              next();
            }
          }
        })
        .catch((error) =>
          res.status(401).json({
            msg: error,
          })
        );
    } else
      res.status(401).json({
        msg: "Authentication required",
      });
  },
};
