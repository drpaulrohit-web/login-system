require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const multer = require("multer");

const app = express();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },

  filename: (req, file, cb) => {
    const uniqueName =
      Date.now() + "-" + Math.round(Math.random() * 1e9);

    cb(null, uniqueName + path.extname(file.originalname));
  }
});

const upload = multer({ storage });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true
    }
  })
);

// MySQL connection
const db = mysql.createConnection({
  host: process.env.MYSQLHOST,
  port: Number(process.env.MYSQLPORT) || 3306,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }

  console.log("MySQL Connected!");
});

// Dashboard protection
app.get("/dashboard", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  res.sendFile(path.join(__dirname, "private", "dashboard.html"));
});

// Serve frontend files

app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Signup API
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Password hash করা
    const hashedPassword = await bcrypt.hash(password, 10);

    // User database-এ save করা
    db.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.status(400).send("এই Email দিয়ে আগে থেকেই account আছে!");
          }

          return res.status(500).send("Database error!");
        }

        res.send("Signup successful!");
      }
    );
  } catch (error) {
    res.status(500).send("Server error!");
  }
});

// Login API
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) {
        return res.status(500).send("Database error!");
      }

      if (results.length === 0) {
        return res.status(400).send("Email পাওয়া যায়নি!");
      }

      const user = results[0];

      const passwordMatch = await bcrypt.compare(
        password,
        user.password
      );

      if (!passwordMatch) {
        return res.status(400).send("Password ভুল!");
      }

      req.session.userId = user.id;

      res.redirect("/dashboard");
    }
  );
});

// Current user API
app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Not logged in"
    });
  }

  db.query(
    "SELECT name, email, profile_photo FROM users WHERE id = ?",
    [req.session.userId],
    (err, results) => {
      if (err) {
        return res.status(500).json({
          message: "Database error"
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      res.json({
        name: results[0].name,
	email: results[0].email,
	profilePhoto: results[0].profile_photo
      });
    }
  );
});

// Upload profile photo
app.post(
  "/upload-profile-photo",
  upload.single("profilePhoto"),
  (req, res) => {
    if (!req.session.userId) {
      return res.status(401).json({
        message: "Not logged in"
      });
    }

    if (!req.file) {
      return res.status(400).json({
        message: "No file uploaded"
      });
    }

    const photoPath = "/uploads/" + req.file.filename;

    db.query(
      "UPDATE users SET profile_photo = ? WHERE id = ?",
      [photoPath, req.session.userId],
      (err) => {
        if (err) {
          return res.status(500).json({
            message: "Database error"
          });
        }

        res.json({
          message: "Profile photo uploaded successfully!",
          profilePhoto: photoPath
        });
      }
    );
  }
);

// Edit Profile API
app.post("/edit-profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Please log in first."
    });
  }

  const { name } = req.body;

  if (!name || name.trim() === "") {
    return res.status(400).json({
      message: "Name cannot be empty."
    });
  }

  db.query(
    "UPDATE users SET name = ? WHERE id = ?",
    [name.trim(), req.session.userId],
    (err) => {
      if (err) {
        return res.status(500).json({
          message: "Could not update profile."
        });
      }

      res.json({
        message: "Profile updated successfully!",
        name: name.trim()
      });
    }
  );
});

// Change Password API
app.post("/change-password", async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Please log in first."
    });
  }

  const { currentPassword, newPassword } = req.body;

  db.query(
    "SELECT password FROM users WHERE id = ?",
    [req.session.userId],
    async (err, results) => {
      if (err) {
        return res.status(500).json({
          message: "Database error."
        });
      }

      if (results.length === 0) {
        return res.status(404).json({
          message: "User not found."
        });
      }

      const passwordMatch = await bcrypt.compare(
        currentPassword,
        results[0].password
      );

      if (!passwordMatch) {
        return res.status(400).json({
          message: "Current password is incorrect."
        });
      }

      const hashedPassword = await bcrypt.hash(
        newPassword,
        10
      );

      db.query(
        "UPDATE users SET password = ? WHERE id = ?",
        [hashedPassword, req.session.userId],
        (updateErr) => {
          if (updateErr) {
            return res.status(500).json({
              message: "Could not update password."
            });
          }

          res.json({
            message: "Password changed successfully!"
          });
        }
      );
    }
  );
});

// Logout API
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send("Logout failed!");
    }

    res.redirect("/");
  });
});

// Start server
app.listen(3000, () => {
  console.log("Server running at http://localhost:3000");
});