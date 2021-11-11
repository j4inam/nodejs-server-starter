"use strict";

exports = module.exports = function (app, mongoose) {
  let AuthenticationSchema = new mongoose.Schema(
    {
      userId: {
        type: String,
        unique: true,
      },
      passwordHash: {
        type: String,
      },
    },
    {
      timestamps: {
        createdAt: "createdAt",
        updatedAt: "updatedAt",
      },
    }
  );

  app.db.model("Authentication", AuthenticationSchema);
};
