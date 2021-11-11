const authService = require("./services/auth");
const authUtils = require("./utils/auth");

exports = module.exports = (app) => {
  //  Verify CORS requests for browser
  app.options("/*", (req, res) => {
    return res.status(200).json();
  });

  app.get("/", (req, res) => {
    res.status(200).json("Server Running");
  });

  // Unverified Requests
  app.post("/api/admin/register", authService.adminRegister);
  app.post("/api/admin/login", authService.adminLogin);

  app.post("/api/user/register", authService.registerUser);
  app.post("/api/user/login", authService.loginUser);

  app.get("/api/user/verify/:id", authService.verifyAccount);

  // Authorized Requests
  app.all("/api/account/*", authUtils.authenticate);

  app.get("/api/account/user-session", (req, res) =>
    authUtils.authenticate(req, res)
  );
};
