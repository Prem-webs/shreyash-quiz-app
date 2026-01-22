const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const port = 3000;

/* ================= DATABASE ================= */

const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://user:password@localhost:5432/quiz_competition',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

/* ================= SESSION ================= */

const sessions = {};

/* ================= MIDDLEWARE ================= */

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const isLoggedIn = (req, res, next) => {
    const sessionId = req.headers['x-session-id'] || req.query.sessionId;
    if (!sessionId || !sessions[sessionId]) {
        return req.accepts('html')
            ? res.redirect('/')
            : res.status(401).json({ message: 'Unauthorized' });
    }
    req.userId = sessions[sessionId].userId;
    req.userRole = sessions[sessionId].role;
    next();
};

const isAdmin = (req, res, next) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Admin only' });
    }
    next();
};

/* ================= AUTH ================= */

app.post('/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'All fields required' });
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO "users" ("full_name","email","password_hash","role","quiz_status") VALUES ($1,$2,$3,$4,$5)',
            [fullName, email, hash, 'student', 'unattempted']
        );
        res.json({ message: 'Registered successfully' });
    } catch (e) {
        if (e.code === '23505') {
            return res.status(409).json({ message: 'Email already exists' });
        }
        res.status(500).json({ message: 'Registration error' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query(
        'SELECT id,password_hash,role,quiz_status FROM "users" WHERE email=$1',
        [email]
    );

    const user = result.rows[0];
    if (!user) return res.status(401).json({ message: 'Invalid login' });

    if (user.role === 'student' && ['completed', 'disqualified'].includes(user.quiz_status)) {
        return res.status(403).json({ message: 'Quiz already completed' });
    }

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ message: 'Invalid login' });

    const sessionId = `s_${user.id}_${Date.now()}`;
    sessions[sessionId] = { userId: user.id, role: user.role };

    res.json({ sessionId, role: user.role });
});

app.post('/logout', isLoggedIn, (req, res) => {
    delete sessions[req.headers['x-session-id']];
    res.json({ message: 'Logged out' });
});

/* ================= ADMIN ================= */

app.get('/admin/metrics', isLoggedIn, isAdmin, async (req, res) => {
    const results = (await pool.query(`
        SELECT 
            u.full_name,
            u.email,
            a.score,
            a.created_at,
            a.end_time
        FROM "attempts" a
        JOIN "users" u ON u.id = a.user_id
        WHERE a.status='completed'
        ORDER BY a.created_at DESC
    `)).rows;

    res.json({ results });
});

/* ================= QUIZ ================= */

app.post('/student/start-quiz', isLoggedIn, async (req, res) => {
    const userId = req.userId;
    const QUIZ_LENGTH = 50;

    const questions = (await pool.query('SELECT id FROM "questions"')).rows;
    if (questions.length < QUIZ_LENGTH) {
        return res.status(400).json({ message: 'Not enough questions' });
    }

    const ids = questions.map(q => q.id).sort(() => Math.random() - 0.5).slice(0, QUIZ_LENGTH);

    await pool.query('UPDATE "users" SET quiz_status=$1 WHERE id=$2', ['started', userId]);

    const attempt = await pool.query(
        'INSERT INTO "attempts" ("user_id","shuffled_questions","status") VALUES ($1,$2,$3) RETURNING id',
        [userId, JSON.stringify(ids), 'started']
    );

    res.json({ attemptId: attempt.rows[0].id, questionIds: ids });
});

app.get('/questions', isLoggedIn, async (req, res) => {
    const ids = req.query.ids.split(',').map(Number);
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');
    const data = await pool.query(
        `SELECT id,question_text,option_a,option_b,option_c,option_d FROM "questions" WHERE id IN (${placeholders})`,
        ids
    );
    res.json(data.rows);
});

app.post('/student/submit-answers', isLoggedIn, async (req, res) => {
    const { attemptId, answers } = req.body;
    const userId = req.userId;

    const attempt = await pool.query(
        'SELECT shuffled_questions FROM "attempts" WHERE id=$1 AND user_id=$2 AND status=$3',
        [attemptId, userId, 'started']
    );

    if (!attempt.rows.length) {
        return res.json({ message: 'Quiz already submitted.' });
    }

    const questionIds = attempt.rows[0].shuffled_questions;
    const placeholders = questionIds.map((_, i) => `$${i + 1}`).join(',');

    const correct = (await pool.query(
        `SELECT id,correct_option FROM "questions" WHERE id IN (${placeholders})`,
        questionIds
    )).rows;

    let score = 0;
    const map = {};
    correct.forEach(q => map[q.id] = q.correct_option);

    questionIds.forEach(id => {
        if (answers[id] && answers[id] === map[id]) score++;
    });

    await pool.query(
        'UPDATE "attempts" SET score=$1,status=$2,end_time=NOW() WHERE id=$3',
        [score, 'completed', attemptId]
    );

    await pool.query(
        'UPDATE "users" SET quiz_status=$1 WHERE id=$2',
        ['completed', userId]
    );

    // 🔒 IMPORTANT: NO SCORE SENT TO STUDENT
    res.json({ message: 'Quiz submitted successfully!' });
});

/* ================= PAGES ================= */

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/student.html', isLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'student.html')));
app.get('/admin.html', isLoggedIn, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

/* ================= START ================= */

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
