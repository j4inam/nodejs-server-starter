const fs = require("fs"),
  path = require("path"),
  Handlebars = require("handlebars"),
  nodemailer = require("nodemailer");

const emailTemplates = {
  VERIFY_ACCOUNT: "verify-account.hbs",
};

const transporterConfig = {
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASSWORD,
  },
  secure: false,
};

const transporter = nodemailer.createTransport(transporterConfig);

// verify connection configuration
transporter.verify(function (error) {
  if (error) {
    console.log(error);
  } else {
    console.log("Mailing server ready");
  }
});

exports = module.exports = {
  sendMail: (receiverEmail, subject, action, templateLocals) => {
    // Open template file
    const source = fs.readFileSync(
      path.join(process.cwd(), "templates/" + emailTemplates[action]),
      "utf8"
    );
    // Create email generator
    var template = Handlebars.compile(source);

    const options = {
      from: `${process.env.APP_NAME} <${process.env.SMTP_EMAIL}>`,
      to: receiverEmail,
      subject,
      html: template(templateLocals), // Process template with locals - {passwordResetAddress}
    };

    return transporter.sendMail(options);
  },
};
