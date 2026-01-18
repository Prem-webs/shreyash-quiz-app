require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const path = require("path");
const db = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;

/* ================= MIDDLEWARE ================= */
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/* ================= AUTH MIDDLEWARE ================= */
function isLoggedIn(req, res, next) {
  const token = req.headers["x-session-id"] || req.query.sessionId;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  db.query(
    "SELECT id, role FROM users WHERE session_token=?",
    [token],
    (err, rows) => {
      if (err || rows.length === 0) {
        return res.status(401).json({ message: "Invalid session" });
      }
      req.user = { userId: rows[0].id, role: rows[0].role };
      next();
    }
  );
}

function isAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin only" });
  }
  next();
}

/* ================= HEALTH CHECK (RENDER) ================= */
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

/* ================= TEST DB ================= */
app.get("/test-db", (req, res) => {
  db.query("SELECT 1", err => {
    if (err) return res.send("❌ MySQL not connected");
    res.send("✅ MySQL connected");
  });
});

/* ================= REGISTER (STUDENT) ================= */
app.post("/register", async (req, res) => {
  const { fullName, email, password } = req.body;
  if (!fullName || !email || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  const hash = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO users (full_name, email, password_hash, role, quiz_status) VALUES (?, ?, ?, 'student', 'unattempted')",
    [fullName, email, hash],
    err => {
      if (err) return res.status(500).json({ message: "Register failed" });
      res.json({ message: "Registered successfully" });
    }
  );
});

/* ================= LOGIN ================= */
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query("SELECT * FROM users WHERE email=?", [email], async (err, rows) => {
    if (err || rows.length === 0) {
      return res.status(401).json({ message: "Invalid login" });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid login" });

    if (user.role === "student" && user.quiz_status !== "unattempted") {
      return res.status(403).json({ message: "Quiz already attempted" });
    }

    const sessionToken = crypto.randomBytes(32).toString("hex");

    db.query(
      "UPDATE users SET session_token=? WHERE id=?",
      [sessionToken, user.id],
      () => {
        res.json({
          message: "Login success",
          role: user.role,
          sessionId: sessionToken
        });
      }
    );
  });
});

/* ================= LOGOUT ================= */
app.post("/logout", isLoggedIn, (req, res) => {
  db.query(
    "UPDATE users SET session_token=NULL WHERE id=?",
    [req.user.userId],
    () => res.json({ message: "Logged out" })
  );
});

/* ================= ADMIN ADD QUESTION ================= */
app.post("/admin/questions", isLoggedIn, isAdmin, (req, res) => {
  const {
    questionText,
    optionA,
    optionB,
    optionC,
    optionD,
    correctOption,
    round = 1
  } = req.body;

  db.query(
    "INSERT INTO questions (question_text, option_a, option_b, option_c, option_d, correct_option, round) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [questionText, optionA, optionB, optionC, optionD, correctOption, round],
    err => {
      if (err) return res.status(500).json({ message: "Add question failed" });
      res.json({ message: "Question added" });
    }
  );
});

/* ================= ROUND 1 START ================= */
app.post("/student/start", isLoggedIn, (req, res) => {
  if (req.user.role !== "student") {
    return res.status(403).json({ message: "Admin cannot start quiz" });
  }

  const userId = req.user.userId;
  const QUIZ_LENGTH = 50;

  db.query("SELECT quiz_status FROM users WHERE id=?", [userId], (e, u) => {
    if (!u || u.length === 0 || u[0].quiz_status !== "unattempted") {
      return res.status(403).json({ message: "Quiz not allowed" });
    }

    db.query(
      "SELECT id FROM questions WHERE round=1 ORDER BY RAND() LIMIT ?",
      [QUIZ_LENGTH],
      (err, qs) => {
        if (!qs || qs.length < QUIZ_LENGTH) {
          return res.status(400).json({ message: "Not enough questions" });
        }

        const ids = qs.map(q => q.id);

        db.query(
          "INSERT INTO attempts (user_id, shuffled_questions, status) VALUES (?, ?, 'started')",
          [userId, JSON.stringify(ids)],
          (err2, r) => {
            db.query("UPDATE users SET quiz_status='started' WHERE id=?", [userId]);
            res.json({
              message: "Round-1 started",
              attemptId: r.insertId,
              questionIds: ids
            });
          }
        );
      }
    );
  });
});

/* ================= ROUND 1 SUBMIT ================= */
app.post("/student/submit", isLoggedIn, (req, res) => {
  const { attemptId, answers } = req.body;
  const userId = req.user.userId;

  db.query(
    "SELECT shuffled_questions FROM attempts WHERE id=? AND user_id=? AND status='started'",
    [attemptId, userId],
    (err, rows) => {
      if (!rows || rows.length === 0) {
        return res.status(400).json({ message: "Invalid attempt" });
      }

      const qIds = JSON.parse(rows[0].shuffled_questions);
      const placeholders = qIds.map(() => "?").join(",");

      db.query(
        `SELECT id, correct_option FROM questions WHERE id IN (${placeholders})`,
        qIds,
        (e, qs) => {
          let score = 0;
          qs.forEach(q => {
            if (answers[q.id] === q.correct_option) score++;
          });

          const qualified = score >= 35;

          db.query(
            "UPDATE attempts SET status='completed', score=?, end_time=NOW() WHERE id=?",
            [score, attemptId]
          );

          db.query(
            "UPDATE users SET quiz_status='completed', round1_score=?, qualified=? WHERE id=?",
            [score, qualified, userId]
          );

          res.json({
            message: qualified
              ? "Qualified for Round-2 🎉"
              : "Not Qualified ❌",
            score,
            qualified
          });
        }
      );
    }
  );
});

/* ================= ROUND 2 START ================= */
app.post("/student/start-round2", isLoggedIn, (req, res) => {
  const userId = req.user.userId;
  const QUIZ_LENGTH = 20;

  db.query("SELECT qualified FROM users WHERE id=?", [userId], (e, u) => {
    if (!u || !u[0].qualified) {
      return res.status(403).json({ message: "Not qualified for Round-2" });
    }

    db.query(
      "SELECT id FROM questions WHERE round=2 ORDER BY RAND() LIMIT ?",
      [QUIZ_LENGTH],
      (err, qs) => {
        if (!qs || qs.length < QUIZ_LENGTH) {
          return res.status(400).json({ message: "Not enough Round-2 questions" });
        }

        const ids = qs.map(q => q.id);
        db.query(
          "INSERT INTO attempts (user_id, shuffled_questions, status) VALUES (?, ?, 'started')",
          [userId, JSON.stringify(ids)],
          (e2, r) => {
            res.json({
              message: "Round-2 started",
              attemptId: r.insertId,
              questionIds: ids
            });
          }
        );
      }
    );
  });
});

/* ================= SERVE HTML ================= */
app.get("/", (_, res) =>
  res.sendFile(path.join(__dirname, "index.html"))
);
app.get("/admin.html", (_, res) =>
  res.sendFile(path.join(__dirname, "admin.html"))
);
app.get("/student.html", (_, res) =>
  res.sendFile(path.join(__dirname, "student.html"))
);

/* ================= START SERVER ================= */
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
