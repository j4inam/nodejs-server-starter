"use strict";

exports = module.exports = (app, mongoose) => {
  let UserSchema = new mongoose.Schema(
    {
      firstName: {
        type: String,
        required: true,
        trim: true,
      },
      lastName: {
        type: String,
        required: true,
        trim: true,
      },
      email: {
        type: String,
        unique: true,
        required: true,
        trim: true,
      },
      password: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Authentication",
      },
      role: {
        type: Number,
        enum: [0, 1, 2],
        default: 0,
      },
      isActive: {
        type: Boolean,
        default: true,
      },
      isVerified: {
        type: Boolean,
        default: false,
      },
    },
    {
      timestamps: {
        createdAt: "createdAt",
        updatedAt: "updatedAt",
      },
    }
  );

  UserSchema.index(
    {
      email: 1,
    },
    {
      unique: true,
    }
  );
  app.db.model("User", UserSchema);
};
