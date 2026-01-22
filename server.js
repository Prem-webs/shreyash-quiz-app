const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

// --- Variable Initialization ---
const app = express();
const port = 3000;

// --- PostgreSQL Connection Pool Setup ---
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://user:password@localhost:5432/quiz_competition',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- Simple Session Storage (In-Memory) ---
const sessions = {};

// --- Middleware setup ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// --- Auth Helpers ---
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
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
};

// --- AUTH ROUTES ---

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

app.post('/logout', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId) delete sessions[sessionId];
    res.json({ message: 'Logged out' });
});

// --- ADMIN METRICS (ALL RESULTS) ---
app.get('/admin/metrics', isLoggedIn, isAdmin, async (req, res) => {
    try {
        // Total participants
        const totalParticipants = (
            await pool.query('SELECT COUNT(id)::int AS total FROM "users"')
        ).rows[0].total;

        // Total questions
        const totalQuestions = (
            await pool.query('SELECT COUNT(id)::int AS total FROM "questions"')
        ).rows[0].total;

        // Completed quizzes
        const completedQuizzes = (
            await pool.query(
                `SELECT COUNT(id)::int AS total FROM "attempts" WHERE status = 'completed'`
            )
        ).rows[0].total;

        // All results
        const results = (
            await pool.query(`
                SELECT 
                    u.full_name,
                    u.email,
                    a.score,
                    a.created_at,
                    a.end_time
                FROM "attempts" a
                JOIN "users" u ON a.user_id = u.id
                WHERE a.status = 'completed'
                ORDER BY a.score DESC, a.end_time ASC
            `)
        ).rows;

        // ✅ VERY IMPORTANT: exact keys admin.html expects
        res.json({
            totalParticipants,
            totalQuestions,
            completedQuizzes,
            results
        });
    } catch (error) {
        console.error('Admin metrics error:', error);
        res.status(500).json({ message: 'Failed to load admin metrics' });
    }
});


// --- ADMIN QUESTION CRUD ---

app.get('/admin/questions', isLoggedIn, isAdmin, async (req, res) => {
    const q = await pool.query('SELECT * FROM "questions" ORDER BY id DESC');
    res.json(q.rows);
});

app.post('/admin/questions', isLoggedIn, isAdmin, async (req, res) => {
    const { questionText, optionA, optionB, optionC, optionD, correctOption } = req.body;

    if (!questionText || !optionA || !optionB || !optionC || !optionD || !correctOption) {
        return res.status(400).json({ message: 'All fields required' });
    }

    await pool.query(
        'INSERT INTO "questions" ("question_text","option_a","option_b","option_c","option_d","correct_option") VALUES ($1,$2,$3,$4,$5,$6)',
        [questionText, optionA, optionB, optionC, optionD, correctOption]
    );

    res.json({ message: 'Question added' });
});

app.delete('/admin/questions/:id', isLoggedIn, isAdmin, async (req, res) => {
    await pool.query('DELETE FROM "questions" WHERE id=$1', [req.params.id]);
    res.json({ message: 'Question deleted' });
});

// --- STUDENT QUIZ ---

app.post('/student/start-quiz', isLoggedIn, async (req, res) => {
    const userId = req.userId;
    const QUIZ_LENGTH = 50;

    const all = (await pool.query('SELECT id FROM "questions"')).rows;
    if (all.length < QUIZ_LENGTH) {
        return res.status(400).json({ message: 'Not enough questions' });
    }

    const ids = all.map(q => q.id).sort(() => 0.5 - Math.random()).slice(0, QUIZ_LENGTH);

    await pool.query('UPDATE "users" SET quiz_status=$1 WHERE id=$2', ['started', userId]);

    const attempt = await pool.query(
        'INSERT INTO "attempts" ("user_id","shuffled_questions","status") VALUES ($1,$2,$3) RETURNING id',
        [userId, JSON.stringify(ids), 'started']
    );

    res.json({ attemptId: attempt.rows[0].id, questionIds: ids });
});

// ✅ IMPORTANT: ORDER PRESERVED (FIX FOR CURRENT QUESTION)
app.get('/questions', isLoggedIn, async (req, res) => {
    const idArray = req.query.ids.split(',').map(id => parseInt(id)).filter(Boolean);
    const placeholders = idArray.map((_, i) => `$${i + 1}`).join(',');

    const result = await pool.query(
        `SELECT id,question_text,option_a,option_b,option_c,option_d FROM "questions" WHERE id IN (${placeholders})`,
        idArray
    );

    const ordered = idArray.map(id => result.rows.find(q => q.id === id));
    res.json(ordered.filter(Boolean));
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

    const ids = attempt.rows[0].shuffled_questions;
    const placeholders = ids.map((_, i) => `$${i + 1}`).join(',');

    const correct = (await pool.query(
        `SELECT id,correct_option FROM "questions" WHERE id IN (${placeholders})`,
        ids
    )).rows;

    let score = 0;
    const map = {};
    correct.forEach(q => map[q.id] = q.correct_option);

    ids.forEach(id => {
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

    // ❌ STUDENT DOES NOT RECEIVE SCORE
    res.json({ message: 'Quiz submitted successfully!' });
});

// --- LEADERBOARD (ADMIN ONLY) ---
app.get('/leaderboard-data', isLoggedIn, isAdmin, async (req, res) => {
    const rows = (await pool.query(`
        SELECT u.full_name, a.score, a.created_at
        FROM "attempts" a
        JOIN "users" u ON a.user_id = u.id
        WHERE a.status='completed'
        ORDER BY a.score DESC, a.end_time ASC
        LIMIT 10
    `)).rows;

    res.json(rows);
});

app.get('/leaderboard.html', isLoggedIn, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'leaderboard.html'));
});

// --- PAGES ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/admin.html', isLoggedIn, isAdmin, (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/student.html', isLoggedIn, (req, res) => res.sendFile(path.join(__dirname, 'student.html')));

// --- START ---
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
