
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors({
  origin: "http://localhost:8080"
}));
app.use(express.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10
});

function createToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({ message: "Please sign in." });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired login." });
  }
}

app.get("/", (req, res) => {
  res.json({ message: "Student Expense Tracker API is running!" });
});

app.get("/api/test", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      success: true,
      message: "Backend and MySQL connected successfully!"
    });
  } catch (error) {
    console.error("Database test failed:", error.message);
    res.status(500).json({ message: "Database connection failed." });
  }
});

app.post("/api/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (
      typeof name !== "string" || !name.trim() ||
      typeof email !== "string" ||
      typeof password !== "string" ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        message: "Enter your name and email, and a password of 8 to 72 characters."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    const [existing] = await pool.execute(
      "SELECT id FROM users WHERE email = ?",
      [cleanEmail]
    );

    if (existing.length > 0) {
      return res.status(409).json({
        message: "An account with this email already exists."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const [result] = await pool.execute(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name.trim(), cleanEmail, passwordHash]
    );

    const user = {
      id: result.insertId,
      name: name.trim(),
      email: cleanEmail
    };

    res.status(201).json({
      message: "Account created successfully!",
      user,
      token: createToken(user)
    });
  } catch (error) {
    if (error.code === "ER_DUP_ENTRY") {
      return res.status(409).json({
        message: "An account with this email already exists."
      });
    }

    console.error("Signup failed:", error.message);
    res.status(500).json({ message: "Could not create the account." });
  }
});

app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Enter your email and password."
      });
    }

    const [users] = await pool.execute(
      "SELECT id, name, email, password FROM users WHERE email = ?",
      [email.trim().toLowerCase()]
    );

    if (
      users.length === 0 ||
      !(await bcrypt.compare(password, users[0].password))
    ) {
      return res.status(401).json({
        message: "Incorrect email or password."
      });
    }

    const user = {
      id: users[0].id,
      name: users[0].name,
      email: users[0].email
    };

    res.json({
      message: "Signed in successfully!",
      user,
      token: createToken(user)
    });
  } catch (error) {
    console.error("Signin failed:", error.message);
    res.status(500).json({ message: "Could not sign in." });
  }
});

app.get("/api/expenses", authenticate, async (req, res) => {
  try {
    const [expenses] = await pool.execute(
      `SELECT id, title, amount, category, expense_date
       FROM expenses
       WHERE user_id = ?
       ORDER BY expense_date DESC, id DESC`,
      [req.user.id]
    );

    res.json(expenses);
  } catch (error) {
    console.error("Fetching expenses failed:", error.message);
    res.status(500).json({ message: "Could not fetch expenses." });
  }
});

app.post("/api/expenses", authenticate, async (req, res) => {
  try {
    const { title, amount, category, expense_date } = req.body;
    const parsedAmount = Number(amount);

    if (
      typeof title !== "string" || !title.trim() ||
      title.trim().length > 150 ||
      typeof category !== "string" || !category.trim() ||
      category.trim().length > 100 ||
      amount === "" || amount === null ||
      !Number.isFinite(parsedAmount) || parsedAmount <= 0 ||
      !Number.isFinite(Number(amount)) ||
      typeof expense_date !== "string" ||
      !/^\d{4}-\d{2}-\d{2}$/.test(expense_date) ||
      !Number.isFinite(Date.parse(expense_date))
    ) {
      return res.status(400).json({
        message: "Enter a valid title, positive amount, category, and date."
      });
    }

    const [result] = await pool.execute(
      `INSERT INTO expenses
       (user_id, title, amount, category, expense_date)
       VALUES (?, ?, ?, ?, ?)`,
      [
        req.user.id,
        title.trim(),
        parsedAmount,
        category.trim(),
        expense_date
      ]
    );

    res.status(201).json({
      message: "Expense saved!",
      id: result.insertId
    });
  } catch (error) {
    console.error("Saving expense failed:", error.message);
    res.status(500).json({ message: "Could not save the expense." });
  }
});

async function startServer() {
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
    throw new Error("Set JWT_SECRET to a private secret of at least 32 characters.");
  }

  await pool.query("SELECT 1");

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Backend running on port ${PORT}`);
    console.log("MySQL connection successful.");
  });
}

startServer().catch((error) => {
  console.error("Server startup failed:", error.message);
  process.exit(1);
});
