"use strict";

exports = module.exports = (app, mongoose) => {
  require("./schema/User")(app, mongoose);
  require("./schema/Authentication")(app, mongoose);
};
