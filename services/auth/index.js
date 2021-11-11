const saltRounds = 10;
const bcrypt = require("bcrypt");
const jose = require("node-jose");
const config = require("../../config");
const mailUtils = require("../../utils/mail");

const createAuthenticationToken = (data) => {
  return new Promise((resolve, reject) => {
    jose.JWE.createEncrypt(
      {
        format: "compact",
      },
      config.JWEKeySet.keys[0]
    )
      .update(JSON.stringify(data))
      .final()
      .then((encyptedKey) => {
        resolve(encyptedKey);
      })
      .catch((error) => {
        console.log("Error", error);
        reject(error);
      });
  });
};

let getAuthToken = (user) => {
  return new Promise((resolve, reject) => {
    createAuthenticationToken(user)
      .then((authorizationToken) => {
        resolve({
          user: user,
          token: authorizationToken,
        });
      })
      .catch((error) => {
        console.log("Error :-", error);
        reject(error);
      });
  });
};

const validateEmail = (email) => {
  let re =
    /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
  return re.test(String(email).toLowerCase());
};

let authService = {
  adminLogin: (req, res) => {
    let workflow = req.app.utility.workflow(req, res);
    workflow.on("validateData", () => {
      if (!req.body.email || !req.body.email.trim()) {
        return res.status(400).json({
          msg: "Email is required",
        });
      }

      if (!validateEmail(req.body.email)) {
        return res.status(401).json({
          msg: "Email or password is invalid or your account has been deactivated.",
        });
      }

      if (!req.body.password) {
        return res.status(400).json({
          msg: "Password is required",
        });
      }

      if (req.body.password.length < 8) {
        return res.status(401).json({
          msg: "Email or password is invalid or your account has been deactivated.",
        });
      }

      workflow.emit("findAdmin");
    });

    workflow.on("findAdmin", () => {
      req.app.db.models.User.findOne({
        email: req.body.email,
        role: { $gte: 1 },
        isActive: true,
      })
        .populate("password", "passwordHash")
        .exec((err, user) => {
          if (err) {
            console.log("Find user err: ", err);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid or your account has been deactivated.",
            });
          }

          if (!user) {
            console.log("Find user: ", user);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid or your account has been deactivated.",
            });
          }

          if (!user.isVerified) {
            console.log("Find user: ", user);
            return res.status(401).json({
              msg: "Login Failed. Your account is pending verification.",
            });
          }

          workflow.emit("checkAdminPassword", user);
        });
    });

    workflow.on("checkAdminPassword", (user) => {
      bcrypt.compare(
        req.body.password,
        user.password.passwordHash,
        (err, result) => {
          if (err) {
            console.log("In bcrypt error", err);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid or your account has been deactivated.",
            });
          }
          console.log("In bcrypt result", JSON.stringify(user));
          if (result) {
            const formattedUser = JSON.parse(JSON.stringify(user));
            delete formattedUser.password;
            getAuthToken(formattedUser).then((userData) => {
              return res.status(200).json(userData);
            });
          } else {
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid or your account has been deactivated.",
            });
          }
        }
      );
    });
    workflow.emit("validateData");
  },

  adminRegister: (req, res) => {
    let workflow = req.app.utility.workflow(req, res);
    workflow.on("validateData", () => {
      if (!req.body.email || !req.body.email.trim()) {
        return res.status(400).json({
          msg: "Email is required",
        });
      }

      if (!validateEmail(req.body.email)) {
        return res.status(400).json({
          msg: "Email is invalid",
        });
      }

      if (!req.body.firstName || !req.body.firstName.trim()) {
        return res.status(400).json({
          msg: "Firstname is required",
        });
      }

      if (!req.body.lastName || !req.body.lastName.trim()) {
        return res.status(400).json({
          msg: "Lastname is required",
        });
      }

      if (!req.body.password) {
        return res.status(400).json({
          msg: "Password is required",
        });
      }

      if (req.body.password.length < 8) {
        return res.status(400).json({
          msg: "Password must be atleast 8 characters",
        });
      }

      workflow.emit("checkEmailAvailable");
    });

    workflow.on("checkEmailAvailable", () => {
      console.log("checkEmailAvailable");
      req.app.db.models.User.findOne({
        email: req.body.email,
      }).exec((err, user) => {
        if (err) {
          console.log("Check email err", err);
          return res.status(400).json({
            msg: "Failed to create admin. Try again",
          });
        }

        if (user) {
          return res.status(400).json({
            msg: "Email already registered. Try logging in with this email and password from the login page.",
          });
        }
        workflow.emit("createAdminObject");
      });
    });

    workflow.on("createAdminObject", () => {
      console.log("createAdminObject");
      let admin = {
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        role: 1,
      };

      bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        if (err) {
          console.log("Password hashing failed", err);
          return res.status(400).json({
            msg: "Failed to create user. Try again",
          });
        }
        console.log("hash", hash);
        workflow.emit("writeAdminToDB", {
          admin,
          hash,
        });
      });
    });

    workflow.on("writeAdminToDB", (adminData) => {
      console.log("writeAdminToDB");
      req.app.db.models.User.create(adminData.admin, (err, admin) => {
        if (err) {
          console.log("Create Admin err", err);
          return res.status(400).json({
            msg: "Failed to create admin. Try again",
          });
        }
        workflow.emit("saveAdminPassword", {
          admin,
          passwordHash: adminData.hash,
        });
      });
    });

    workflow.on("saveAdminPassword", (userObject) => {
      console.log("saveAdminPassword");
      const authData = {
        userId: userObject.admin._id,
        passwordHash: userObject.passwordHash,
      };

      req.app.db.models.Authentication.create(authData, (err, authObject) => {
        if (err) {
          console.log(err);
          return res.status(400).json({
            msg: "Failed to create admin. Try again",
          });
        }
        workflow.emit("setPassworIDToAdmin", {
          user: userObject.admin,
          authObject,
        });
      });
    });

    workflow.on("setPassworIDToAdmin", (userData) => {
      req.app.db.models.User.updateOne(
        {
          _id: userData.admin._id,
        },
        {
          $set: {
            password: userData.authObject._id,
          },
        }
      ).exec((err) => {
        if (err) {
          console.log("Link password err", err);
          return res.status(400).json({
            msg: "Failed to create admin. Try again!",
          });
        }
        workflow.emit("sendVerificationMail", userData);
      });
    });

    workflow.on("sendVerificationMail", (userData) => {
      const subject = `Verify your ${process.env.APP_NAME} account`;

      const templateLocals = {
        username: userData.user.firstName,
        appName: process.env.APP_NAME,
        verificationLink: `http://${process.env.APP_HOST}:${process.env.APP_PORT}/api/user/verify/${userData.user._id}`,
      };
      mailUtils
        .sendMail(
          userData.user.email,
          subject,
          "VERIFY_ACCOUNT",
          templateLocals
        )
        .then(() => {
          res.status(200).json();
        })
        .catch((err) => {
          console.log("Sendmail err", err);
        });
    });
    workflow.emit("validateData");
  },

  loginUser: (req, res) => {
    let workflow = req.app.utility.workflow(req, res);
    workflow.on("validateData", () => {
      if (!req.body.email || !req.body.email.trim()) {
        return res.status(401).json({
          msg: "Email is required",
        });
      }

      if (!validateEmail(req.body.email)) {
        return res.status(401).json({
          msg: "Email or password is invalid.",
        });
      }

      if (!req.body.password) {
        return res.status(401).json({
          msg: "Password is required",
        });
      }

      if (req.body.password.length < 8) {
        return res.status(401).json({
          msg: "Email or password is invalid.",
        });
      }

      workflow.emit("findUser");
    });

    workflow.on("findUser", () => {
      req.app.db.models.User.findOne({
        email: req.body.email,
        isActive: true,
      })
        .populate("password", "passwordHash")
        .exec((err, user) => {
          if (err) {
            console.log("Find user err: ", err);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid.",
            });
          }

          if (!user) {
            console.log("Find user: ", user);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid.",
            });
          }

          if (!user.isActive) {
            console.log("Find user: ", user);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid or your account has been deactivated.",
            });
          }

          workflow.emit("checkUserPassword", user);
        });
    });

    workflow.on("checkUserPassword", (user) => {
      bcrypt.compare(
        req.body.password,
        user.password.passwordHash,
        (err, result) => {
          if (err) {
            console.log("In bcrtpt error", err);
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid.",
            });
          }
          console.log("In bcrypt result", JSON.stringify(user));
          if (result) {
            const formattedUser = JSON.parse(JSON.stringify(user));
            delete formattedUser.password;
            getAuthToken(formattedUser).then((userData) => {
              return res.status(200).json(userData);
            });
          } else {
            return res.status(401).json({
              msg: "Login Failed. Email or password is invalid.",
            });
          }
        }
      );
    });
    workflow.emit("validateData");
  },

  registerUser: (req, res) => {
    let workflow = req.app.utility.workflow(req, res);
    workflow.on("validateData", () => {
      if (!req.body.email || !req.body.email.trim()) {
        return res.status(400).json({
          msg: "Email is required",
        });
      }

      if (!validateEmail(req.body.email)) {
        return res.status(400).json({
          msg: "Email is invalid",
        });
      }

      if (!req.body.firstName || !req.body.firstName.trim()) {
        return res.status(400).json({
          msg: "Firstname is required",
        });
      }

      if (!req.body.lastName || !req.body.lastName.trim()) {
        return res.status(400).json({
          msg: "Lastname is required",
        });
      }

      if (!req.body.password) {
        return res.status(400).json({
          msg: "Password is required",
        });
      }

      if (req.body.password.length < 8) {
        return res.status(400).json({
          msg: "Password must be atleast 8 characters",
        });
      }

      workflow.emit("checkEmailAvailable");
    });

    workflow.on("checkEmailAvailable", () => {
      console.log("checkEmailAvailable");
      req.app.db.models.User.findOne({
        email: req.body.email,
      }).exec((err, user) => {
        if (err) {
          console.log("Check email err", err);
          return res.status(400).json({
            msg: "Failed to create admin. Try again",
          });
        }

        if (user) {
          return res.status(400).json({
            msg: "Email already registered. Try logging in with this email and password from the login page.",
          });
        }

        workflow.emit("createUserObject");
      });
    });

    workflow.on("createUserObject", () => {
      console.log("createUserObject", req.body);
      let user = {
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
      };

      bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
        if (err) {
          console.log("Password hashing failed", err);
          return res.status(400).json({
            msg: "Failed to create user. Try again",
          });
        }
        console.log("hash", hash);
        workflow.emit("writeUserToDB", {
          user,
          hash,
        });
      });
    });

    workflow.on("writeUserToDB", (userData) => {
      console.log("writeUserToDB");
      req.app.db.models.User.create(userData.user, (err, user) => {
        if (err) {
          console.log("Create User err", err);
          return res.status(400).json({
            msg: "Failed to create user. Try again",
          });
        }
        workflow.emit("saveUserPassword", {
          user,
          passwordHash: userData.hash,
        });
      });
    });

    workflow.on("saveUserPassword", (userObject) => {
      console.log("saveUserPassword");
      const authData = {
        userId: userObject.user._id,
        passwordHash: userObject.passwordHash,
      };

      req.app.db.models.Authentication.create(authData, (err, authObject) => {
        if (err) {
          console.log(err);
          return res.status(400).json({
            msg: "Failed to create user. Try again",
          });
        }
        workflow.emit("setPassworIDToUser", {
          user: userObject.user,
          authObject,
        });
      });
    });

    workflow.on("setPassworIDToUser", (userData) => {
      req.app.db.models.User.updateOne(
        {
          _id: userData.user._id,
        },
        {
          $set: {
            password: userData.authObject._id,
          },
        }
      ).exec((err) => {
        if (err) {
          console.log("Link password err", err);
          return res.status(400).json({
            msg: "Failed to create user. Try again!",
          });
        }
        workflow.emit("sendVerificationMail", userData);
      });
    });

    workflow.on("sendVerificationMail", (userData) => {
      const subject = `Verify your ${process.env.APP_NAME} account`;

      const templateLocals = {
        username: userData.user.firstName,
        appName: process.env.APP_NAME,
        verificationLink: `http://${process.env.APP_HOST}:${process.env.APP_PORT}/api/user/verify/${userData.user._id}`,
      };
      mailUtils
        .sendMail(
          userData.user.email,
          subject,
          "VERIFY_ACCOUNT",
          templateLocals
        )
        .then(() => {
          res.status(200).json();
        })
        .catch((err) => {
          console.log("Sendmail err", err);
        });
    });
    workflow.emit("validateData");
  },
  verifyAccount: (req, res) => {
    var id = req.params.id;

    if (!id) {
      return res.status(401).json({
        msg: "Verification token is required.",
      });
    }

    req.app.db.models.User.updateOne(
      {
        _id: id,
      },
      {
        $set: {
          isVerified: true,
        },
      }
    ).exec((err) => {
      if (err) {
        return res.status(400).json({
          msg: "Failed to verify account. Try again!",
        });
      }
      return res.status(200).json();
    });
  },
};
module.exports = authService;
