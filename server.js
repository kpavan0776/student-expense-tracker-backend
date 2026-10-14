
require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

// Allow requests from the deployed frontend and local development.
const allowedOrigins = [
  "https://student-expense-tracker-frontend-8adut0mn8-acme-77ae2.vercel.app",
  "https://student-expense-tracker-frontend-five.vercel.app",
  "http://localhost:8080",
  "http://localhost:5173"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Origin not allowed by CORS: " + origin));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json());

// Cloud MySQL database connection
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 4000),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  ssl: {
    minVersion: "TLSv1.2"
  }
});

// Verify login token
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication token missing"
    });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        message: "Invalid or expired token"
      });
    }

    req.user = user;
    next();
  });
}

// API home
app.get("/", (req, res) => {
  res.send("Student Expense Tracker API is running!");
});

// Test API and database connection
app.get("/api/test", async (req, res) => {
  try {
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();

    res.json({
      success: true,
      message: "Database connection successful"
    });
  } catch (error) {
    console.error("Database test failed:", error.message);

    res.status(500).json({
      success: false,
      message: "Database connection failed"
    });
  }
});

// Sign up
app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Name, email and password are required"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must contain at least 6 characters"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const [existingUsers] = await pool.execute(
      "SELECT id FROM users WHERE email = ?",
      [normalizedEmail]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name.trim(), normalizedEmail, hashedPassword]
    );

    const token = jwt.sign(
      { id: result.insertId, email: normalizedEmail },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(201).json({
      message: "Account created successfully",
      token,
      user: {
        id: result.insertId,
        name: name.trim(),
        email: normalizedEmail
      }
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        message: "An account with this email already exists"
      });
    }

    res.status(500).json({
      message: "Unable to create account. Please try again."
    });
  }
});

// Sign in
app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        message: "Email and password are required"
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const [users] = await pool.execute(
      "SELECT id, name, email, password FROM users WHERE email = ?",
      [normalizedEmail]
    );

    if (users.length === 0) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const user = users[0];

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password"
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Signed in successfully",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.error("Signin error:", error.message);

    res.status(500).json({
      message: "Unable to sign in. Please try again."
    });
  }
});

// Get the signed-in user's expenses
app.get("/api/expenses", authenticateToken, async (req, res) => {
  try {
    const [expenses] = await pool.execute(
      `SELECT id, title, amount, category, date
       FROM expenses
       WHERE user_id = ?
       ORDER BY date DESC, id DESC`,
      [req.user.id]
    );

    res.json(expenses);
  } catch (error) {
    console.error("Get expenses error:", error.message);

    res.status(500).json({
      message: "Unable to retrieve expenses"
    });
  }
});

// Add an expense
app.post("/api/expenses", authenticateToken, async (req, res) => {
  try {
    const { title, amount, category, date } = req.body;

    if (
      !title ||
      amount === undefined ||
      amount === null ||
      !Number.isFinite(Number(amount)) ||
      Number(amount) <= 0 ||
      !category ||
      !date
    ) {
      return res.status(400).json({
        message: "Please provide a valid title, amount, category and date"
      });
    }

    const [result] = await pool.execute(
      `INSERT INTO expenses
       (user_id, title, amount, category, date)
       VALUES (?, ?, ?, ?, ?)`,
      [
        req.user.id,
        title.trim(),
        Number(amount),
        category,
        date
      ]
    );

    res.status(201).json({
      message: "Expense added successfully",
      id: result.insertId
    });
  } catch (error) {
    console.error("Add expense error:", error.message);

    res.status(500).json({
      message: "Unable to save expense"
    });
  }
});

// Start server
async function startServer() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    console.error("JWT_SECRET must be set to at least 32 characters.");
    process.exit(1);
  }

  try {
    const connection = await pool.getConnection();
    await connection.ping();
    connection.release();

    console.log("Database connection successful.");
  } catch (error) {
    console.error("Database connection check failed:", error.message);
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

startServer();
