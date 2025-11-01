const express = require("express");
const session = require("express-session");
const env = require("dotenv");
require("dotenv").config();
const mysql = require("mysql2");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const flash = require("express-flash");
const { userInfo } = require("os");
const speakeasy = require("speakeasy");
const qrcode = require("qrcode");
const app = express();
const port = 3000;

const dbhost = process.env.DB_HOST;
const dbport = process.env.DB_PORT;
const dbuser = process.env.DB_USER;
const dbpassword = process.env.DB_PASSWORD;
const dbname = process.env.DB_NAME;

const mailhost = process.env.MAIL_HOST;
const mailuser = process.env.MAIL_USER;
const mailpassword = process.env.MAIL_PASSWORD;
const mailoriginaddress = process.env.MAIL_ORIGIN_ADDRESS;

let conn;

function connectToDatabase() {
  conn = mysql.createPool({
    host: dbhost,
    port: dbport,
    user: dbuser,
    password: dbpassword,
    database: dbname,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });
  conn.getConnection((err, res) => {
    if (err) {
      console.error("❌DB CONN", err);
    } else {
      console.log("✅DB CONN", res);
      res.release();
    }
  });
}
connectToDatabase();

app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(flash());

app.get("/", (req, res) => {
  const user = req.session.user || null;
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  res.render("index", {
    title: "Home",
    user: user,
    successMessages: successMessages,
    errorMessages: errorMessages,
  });
});

app.get("/register", (req, res) => {
  res.render("register", { title: "Register" });
});

app.get("/login", (req, res) => {
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  res.render("login", {
    title: "Login",
    successMessages: successMessages,
    errorMessages: errorMessages,
  });
});

app.get("/dashboard", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");

  res.render("dashboard", {
    title: "Dashboard",
    user: req.session.user,
    successMessages: successMessages,
    errorMessages: errorMessages,
  });
});

app.post("/register", (req, res) => {
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;
  const role = "user";
  const verification_token = crypto.randomBytes(32).toString("hex");
  conn.query(
    "INSERT INTO users (email, username, password, role, verification_token, verified) VALUES (?,?,?,?,?,FALSE)",
    [email, username, password, role, verification_token],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.send("There was a problem with your registration");
      } else {
        const userId = results.insertId;
        logAuditEvent(
          userId,
          "user_register",
          { username: username, email: email, password: password },
          req.ip
        );
        const transporter = nodemailer.createTransport({
          host: `${mailhost}`,
          port: 465,
          secure: true,
          auth: {
            user: `${mailuser}`,
            pass: `${mailpassword}`,
          },
        });
        async function emailfunction() {
          const info = await transporter.sendMail({
            from: `"Jauni.de - Mail System" <${mailoriginaddress}>`,
            to: `${email}`,
            subject: "Account Activation",
            text: `Activate html to see relevant content`,
            html: `
                  <p>Here's the link to activate your account:</p>
                  <p><a href="http://localhost:3000/verify-mail?token=${verification_token}">Activate Account</a></p>
                  `,
          });
          logAuditEvent(
            userId,
            "user_register_email",
            {
              username: username,
              email: email,
              password: password,
              a: info.accepted,
              b: info.envelope,
              c: info.messageId,
              d: info.pending,
              e: info.rejected,
              f: info.response,
            },
            req.ip
          );
        }
        emailfunction().catch(console.error);

        req.flash(
          "success",
          "Registration sucessful. Please check your inbox to verify your account"
        );
        return res.redirect("/login");
      }
    }
  );
});

app.get("/verify-mail", (req, res) => {
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  const verification_token = req.query.token;
  if (!verification_token) {
    req.flash("error", "token is missing");
    return res.redirect("/login");
  } else {
    conn.query(
      "UPDATE users SET verification_token = NULL, verified = TRUE WHERE verification_token = ?",
      [verification_token],
      (err, result) => {
        logAuditEvent(
          null,
          "email_verified",
          { token: verification_token },
          req.ip
        );
        req.flash("success", "Email verified. You are now able to login.");
        res.redirect("/login");
      }
    );
  }
});

app.get("/verify-new-mail", (req, res) => {
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  const email_change_token = req.query.token;
  if (!email_change_token) {
    req.flash("error", "token is missing");
    return res.redirect("/login");
  } else {
    conn.query(
      "UPDATE users SET email = new_email, new_email = NULL, email_change_token = NULL WHERE email_change_token = ?",
      [email_change_token],
      (err, result) => {
        logAuditEvent(
          null,
          "email_change_confirmed",
          { token: email_change_token },
          req.ip
        );
        req.flash("success", "Email changed");
        res.redirect("/account");
      }
    );
  }
});

app.post("/login", (req, res) => {
  const identifier = req.body.identifier;
  const password = req.body.password;
  conn.query(
    "SELECT * FROM users WHERE email = ? OR username = ?",
    [identifier, identifier],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.send("No email/username found in the database");
      }
      if (results.length == 0) {
        req.flash("error", "Email/Username not found");
        return res.redirect("/login");
      } else if (results[0].password == password) {
        if (!results[0].verified) {
          req.flash("error", "Please verify your email before logging in.");
          return res.redirect("/login");
        }
        if (results[0].twofa_enabled) {
          req.session.temp_user = results[0];
          return res.redirect("/2fa/login");
        }
        conn.query(
          "UPDATE users SET last_login = NOW() WHERE email = ? OR username = ?",
          [identifier, identifier]
        );
        logAuditEvent(
          results[0].id,
          "login_sucess",
          { userAgent: req.headers["user-agent"] },
          req.ip
        );
        req.session.user = {
          id: results[0].id,
          email: results[0].email,
          username: results[0].username,
          role: results[0].role,
        };
        return res.redirect("/dashboard");
      } else {
        logAuditEvent(
          results[0].id,
          "login_failure",
          { identifier: identifier, password: password },
          req.ip
        );
        req.flash("error", "Wrong password");
        return res.redirect("/login");
      }
    }
  );
});

app.get("/2fa/login", (req, res) => {
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  res.render("2fa-login", {
    title: "2FA",
    successMessages: successMessages,
    errorMessages: errorMessages,
  });
});

app.post("/2fa/login", (req, res) => {
  const user = req.session.temp_user;
  if (!user) {
    req.flash("error", "Session expired. Please log in again.");
    return res.redirect("/login");
  }
  const verified = speakeasy.totp.verify({
    secret: user.twofa_secret,
    encoding: "base32",
    token: req.body.code,
  });
  if (verified) {
    conn.query("UPDATE users SET last_login = NOW() WHERE id = ?", [user.id]);
    logAuditEvent(
      user.id,
      "login_2fa_success",
      { userAgent: req.headers["user-agent"] },
      req.ip
    );
    req.flash("success", "✅2FA Code");
    req.session.user = {
      id: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
    };
    delete req.session.temp_user;
    return res.redirect("/dashboard");
  } else {
    logAuditEvent(
      user.id,
      "login_2fa_failure",
      { attemptedCode: req.body.code },
      req.ip
    );
    req.flash("error", "❌2FA Code");
    return res.redirect("/2fa/login");
  }
});

app.post("/logout", (req, res) => {
  logAuditEvent(req.session.user.id, "logout", {}, req.ip);
  req.session.destroy(() => {
    return res.redirect("/");
  });
});

app.get("/forgot-password", (req, res) => {
  const user = req.session.user || null;
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  res.render("forgot-password", {
    title: "Forgot Password",
    user: user,
    successMessages: successMessages,
    errorMessages: errorMessages,
  });
});

app.post("/forgot-password", (req, res) => {
  const emailvalue = req.body.email;
  conn.query(
    "SELECT * FROM users WHERE email = ?",
    [emailvalue],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.send("No email found in the database");
      }
      if (results.length == 0) {
        req.flash("error", "email not found");
        return res.redirect("/forgot-password");
      } else {
        const reset_token = crypto.randomBytes(32).toString("hex");
        const reset_expires = new Date(Date.now() + 3600000);
        conn.query(
          "UPDATE users SET reset_token = ?, reset_expires = ? WHERE email = ?",
          [reset_token, reset_expires, emailvalue],
          (err2) => {
            if (err2) {
              console.error(err2);
              return res.send("No email found in the database");
            } else {
              logAuditEvent(
                results[0].id,
                "password_reset_requested",
                {
                  email: emailvalue,
                  reset_token: reset_token,
                  reset_expires: reset_expires,
                },
                req.ip
              );
              const transporter = nodemailer.createTransport({
                host: `${mailhost}`,
                port: 465,
                secure: true,
                auth: {
                  user: `${mailuser}`,
                  pass: `${mailpassword}`,
                },
              });

              async function email() {
                const info = await transporter.sendMail({
                  from: `"Jauni.de - Mail System" <${mailoriginaddress}>`,
                  to: `${emailvalue}`,
                  subject: "Password Reset",
                  text: `Activate html to see relevant content`,
                  html: `
                  <p>Here's the link to reset your password:</p>
                  <p><a href="http://localhost:3000/reset-password?token=${reset_token}">Reset Password</a></p>
                  <p>This Link is valid until: ${reset_expires}</p>
                  `,
                });

                console.log("Message sent: %s", info.messageId);
              }

              email().catch(console.error);
              req.flash("success", "Check your inbox");
              return res.redirect("/forgot-password");
            }
          }
        );
      }
    }
  );
});

app.get("/reset-password", (req, res) => {
  const user = req.session.user || null;
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  const reset_token = req.query.token;
  if (!reset_token) {
    req.flash("error", "token is missing");
    return res.redirect("/reset-password");
  } else {
    res.render("reset-password", {
      title: "Reset Password",
      token: reset_token,
      user: user,
      successMessages: successMessages,
      errorMessages: errorMessages,
    });
  }
});
app.post("/reset-password", (req, res) => {
  const reset_token = req.body.token;
  const newPassword = req.body.password;
  conn.query(
    "SELECT * FROM users WHERE reset_token = ?",
    [reset_token],
    (err, results) => {
      if (err) {
        console.error(err);
        return res.send("No token found in the database");
      }
      if (results.length == 0) {
        req.flash("error", "token not found");
        return res.redirect("/reset-password");
      } else {
        const expirationDate = new Date(results[0].reset_expires);
        if (expirationDate.getTime() < Date.now()) {
          return res.send("Token expired");
        } else {
          conn.query(
            "UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE reset_token = ?",
            [newPassword, reset_token],
            (err2) => {
              if (err2) {
                console.error(err2);
                return res.send("Error updating password");
              } else {
                logAuditEvent(
                  results[0].id,
                  "password_reset_confirmed",
                  { newPassword: newPassword },
                  req.ip
                );
                req.flash("success", "Password successfully changed");
                return res.redirect("/");
              }
            }
          );
        }
      }
    }
  );
});

app.get("/admin-dashboard", (req, res) => {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.redirect("/");
  }
  conn.query("SELECT * FROM users", (err, results1) => {
    conn.query("SELECT * FROM audit_logs", (err, results6) => {
      res.render("admin-dashboard", {
        title: "Admin-Dashboard",
        user: req.session.user,
        users: results1,
        result: "",
        audit_logs: results6,
      });
    });
  });
});

app.post("/delete-user", (req, res) => {
  const userId = req.body.id;
  const adminId = req.session.user.id;
  conn.query(
    "SELECT username, email FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      const deletedUser = results[0];
      conn.query(
        "UPDATE audit_logs SET user_id = NULL WHERE user_id = ?",
        [userId],
        (err) => {
          conn.query(
            "DELETE FROM users WHERE id = ?",
            [userId],
            (err, result) => {
              logAuditEvent(
                adminId,
                "account_deletion_by_admin",
                {
                  deletedUser: deletedUser.username,
                  deletedEmail: deletedUser.email,
                  adminUsername: req.session.user.username,
                  adminEmail: req.session.user.email,
                },
                req.ip
              );
              return res.redirect("/admin-dashboard");
            }
          );
        }
      );
    }
  );
});

app.post("/delete-account", (req, res) => {
  const userId = req.session.user.id;
  const username = req.session.user.username;
  const email = req.session.user.email;
  logAuditEvent(
    userId,
    "account_deletion_by_user",
    { username: username, email: email },
    req.ip
  );
  conn.query(
    "UPDATE audit_logs SET user_id = NULL WHERE user_id = ?",
    [userId],
    (err) => {
      conn.query("DELETE FROM users WHERE id = ?", [userId], (err, result) => {
        req.session.destroy(() => {
          return res.redirect("/");
        });
      });
    }
  );
});

app.post("/change-password", (req, res) => {
  const userId = req.session.user.id;
  const newpassword = req.body.newpassword;
  conn.query(
    "SELECT password FROM users WHERE id = ?",
    [userId],
    (err, results1) => {
      const oldPassword = results1[0].password;
      conn.query(
        "UPDATE users SET password = ? WHERE id = ?",
        [newpassword, userId],
        (err, results2) => {
          logAuditEvent(
            req.session.user.id,
            "Change_Password",
            { changes: { password: { from: oldPassword, to: newpassword } } },
            req.ip
          );
          req.flash("success", "Password changed");
          return res.redirect("/account");
        }
      );
    }
  );
});

app.post("/change-username", (req, res) => {
  const userId = req.session.user.id;
  const newUsername = req.body.newUsername;
  conn.query(
    "SELECT username FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      const oldUsername = results[0].username;
      conn.query(
        "UPDATE users SET username = ? WHERE id = ?",
        [newUsername, userId],
        (err, results) => {
          logAuditEvent(
            req.session.user.id,
            "Change_username",
            { changes: { username: { from: oldUsername, to: newUsername } } },
            req.ip
          );
          req.session.user.username = newUsername;
          req.flash("success", "Username changed");
          return res.redirect("/account");
        }
      );
    }
  );
});

app.post("/change-email", (req, res) => {
  const userId = req.session.user.id;
  const newEmail = req.body.newEmail;
  const email_token = crypto.randomBytes(32).toString("hex");
  conn.query(
    "UPDATE users SET new_email = ?, email_change_token = ? WHERE id = ?",
    [newEmail, email_token, userId],
    (err, results) => {
      logAuditEvent(
        userId,
        "change_email_request",
        { oldEmail: req.session.user.email, newEmail: newEmail },
        req.ip
      );
      const transporter = nodemailer.createTransport({
        host: `${mailhost}`,
        port: 465,
        secure: true,
        auth: {
          user: `${mailuser}`,
          pass: `${mailpassword}`,
        },
      });
      async function emailfunction() {
        const info = await transporter.sendMail({
          from: `"Jauni.de - Mail System" <${mailoriginaddress}>`,
          to: `${newEmail}`,
          subject: "Email Address Change",
          text: `Activate html to see relevant content`,
          html: `
                  <p>Here's the link to confirm the change of email address:</p>
                  <p><a href="http://localhost:3000/verify-new-mail?token=${email_token}">Change Email Address</a></p>
                  `,
        });
        console.log("Message sent: %s", info.messageId);
      }
      emailfunction();
      req.flash("success", "Email was sent to Inbox of new Email Address");
      return res.redirect("/account");
    }
  );
});

app.get("/account", (req, res) => {
  const successMessages = req.flash("success");
  const errorMessages = req.flash("error");
  if (!req.session.user) {
    return res.redirect("/");
  }
  const userId = req.session.user.id;
  conn.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    res.render("account", {
      title: "Account",
      user: results[0],
      successMessages: successMessages,
      errorMessages: errorMessages,
    });
  });
});

app.get("/2fa/setup", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  const userId = req.session.user.id;
  conn.query(
    "SELECT twofa_enabled FROM users WHERE id = ?",
    [userId],
    (err, results) => {
      const user = results[0];
      if (user.twofa_enabled) {
        return res.render("2fa", {
          title: "2FA",
          qrcode: null,
          secret: null,
          message: "2FA is already activated",
        });
      } else {
        var secret = speakeasy.generateSecret({ name: "Auth_System" });
        qrcode.toDataURL(secret.otpauth_url, function (err, data_url) {
          req.session.temp_secret = secret.base32;
          return res.render("2fa", {
            title: "2FA Setup",
            user: req.session.user,
            qrcode: data_url,
            message: null,
          });
        });
      }
    }
  );
});

app.get("/2fa/verify", (req, res) => {
  return res.redirect("/");
});

app.post("/2fa/verify", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  const code = req.body.code;
  const verified = speakeasy.totp.verify({
    secret: req.session.temp_secret,
    encoding: "base32",
    token: code,
    window: 1,
  });
  if (!verified) {
    return res.render("2fa", {
      user: req.session.user,
      title: "2FA Setup",
      qrcode: null,
      secret: null,
      message: "Invalid code. Please try again.",
    });
  }
  const userId = req.session.user.id;
  conn.query(
    "UPDATE users SET twofa_enabled = 1, twofa_secret = ? WHERE id = ?",
    [req.session.temp_secret, userId],
    (err) => {
      delete req.session.temp_secret;
      logAuditEvent(
        userId,
        "user_2fa_activated",
        {
          username: req.session.user.username,
          email: req.session.user.email,
          password: req.session.user.password,
        },
        req.ip
      );
      req.flash("success", "2FA was successfully enabled");
      return res.redirect("/dashboard");
    }
  );
});

function logAuditEvent(userId, action, details, ip) {
  conn.query(
    "INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?,?,?,?)",
    [userId, action, JSON.stringify(details), ip]
  );
}

app.post("/2fa/deactivate", (req, res) => {
  userId = req.session.user.id;
  conn.query(
    "UPDATE users SET twofa_enabled = 0, twofa_secret = NULL WHERE id = ?",
    [userId],
    (err, results) => {
      logAuditEvent(
        userId,
        "user_2fa_deactivated",
        {
          username: req.session.user.username,
          email: req.session.user.email,
          password: req.session.user.password,
        },
        req.ip
      );
      req.session.user.twofa_enabled = 0;
      req.session.user.twofa_secret = null;
      return res.redirect("/account");
    }
  );
});

app.get("/activity", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/");
  }
  conn.query(
    "SELECT * FROM audit_logs WHERE user_id = ?",
    [req.session.user.id],
    (err, results) => {
      res.render("activity", {
        title: "Activity",
        audit_logs: results,
        user: req.session.user,
      });
    }
  );
});

app.listen(port, () => {
  console.log(`Server is running at http://localhost:${port}`);
});
