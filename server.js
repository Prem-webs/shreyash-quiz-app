const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg'); // Switched to PostgreSQL library
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from .env file
dotenv.config();

// --- Variable Initialization ---
const app = express();
const port = 3000;

// --- PostgreSQL Connection Pool Setup ---
// Renders automatically provides the DATABASE_URL environment variable from your Neon connection string.
// We fall back to a local connection string if not running on Render.
const pool = new Pool({
    connectionString: process.env.DATABASE_URL || 'postgres://user:password@localhost:5432/quiz_competition',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false // Use SSL on Render
});

// --- Simple Session Storage (In-Memory) ---
const sessions = {}; // sessionId -> { userId, role, expiration }

// --- Middleware setup ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Helper function to check login status
const isLoggedIn = async (req, res, next) => { // Made async to check DB on fail
    const sessionId = req.headers['x-session-id'] || req.query.sessionId;

    if (!sessionId || !sessions[sessionId]) {
        return req.accepts('html') ? res.redirect(process.env.NODE_ENV === 'production' ? '/' : 'http://localhost:3000/?error=unauthorized') : res.status(401).json({ message: 'Unauthorized. Please log in.' });
    }

    req.userId = sessions[sessionId].userId;
    req.userRole = sessions[sessionId].role;
    next();
};

// Helper function to check admin role
const isAdmin = (req, res, next) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ message: 'Forbidden. Admin access required.' });
    }
    next();
};

// --- TEMP DATABASE CONNECTION TEST ROUTE ---
app.get('/test-db', async (req, res) => {
    try {
        const client = await pool.connect();
        client.release();
        res.json({ message: 'Database connected successfully!', solution: 2 });
    } catch (error) {
        console.error('Failed to connect to the database:', error.code, error.message);
        res.status(500).json({ message: 'Failed to connect to the database.', error: error.code });
    }
});
// --- END TEST ROUTE ---

// --- AUTHENTICATION ROUTES (Login & Register) ---

app.post('/register', async (req, res) => {
    const { fullName, email, password } = req.body;
    const role = 'student'; 

    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        // Uses double quotes for PostgreSQL compatibility
        const result = await pool.query(
            'INSERT INTO "users" ("full_name", "email", "password_hash", "role", "quiz_status") VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [fullName, email, passwordHash, role, 'unattempted']
        );
        res.status(201).json({ message: 'Registration successful. Please log in.' });
    } catch (error) {
        if (error.code === '23505') { // PostgreSQL unique constraint violation error code
            return res.status(409).json({ message: 'This email is already registered.' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(`[LOGIN DEBUG] Attempt for: ${email}`); 

    try {
        // Uses double quotes for PostgreSQL compatibility
        const result = await pool.query('SELECT id, password_hash, role, quiz_status FROM "users" WHERE email = $1', [email]);
        const user = result.rows[0];

        if (!user) {
            console.log(`[LOGIN DEBUG] DB Hash fetched: User not found`); 
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        
        // --- Lockout Check Bypass (Admin) ---
        if (user.role === 'student') {
            if (user.quiz_status === 'completed' || user.quiz_status === 'disqualified') {
                return res.status(403).json({ message: 'Access denied. You have already completed or been disqualified from the quiz.' });
            }
        }
        // --- End Lockout Check ---

        console.log(`[LOGIN DEBUG] DB Hash fetched: ${user.password_hash}`);
        const match = await bcrypt.compare(password, user.password_hash);
        console.log(`[LOGIN DEBUG] Password match result: ${match}`); 

        if (match) {
            const sessionId = `s${user.id}_${Date.now()}`;
            sessions[sessionId] = { userId: user.id, role: user.role, expiration: Date.now() + 3600000 }; 
            res.json({
                message: 'Login successful.',
                role: user.role,
                sessionId: sessionId
            });
        } else {
            res.status(401).json({ message: 'Invalid email or password.' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login.' });
    }
});

app.post('/logout', (req, res) => {
    const sessionId = req.headers['x-session-id'];
    if (sessionId && sessions[sessionId]) {
        delete sessions[sessionId];
    }
    res.json({ message: 'Logged out successfully.' });
});

// --- ADMIN API ROUTES ---

// Get total participants and all quiz results for admin dashboard metrics
app.get('/admin/metrics', isLoggedIn, isAdmin, async (req, res) => {
    try {
        // FIXED: Using COUNT(*) and retrieving the value explicitly for Postgres
        const totalParticipantsRows = await pool.query('SELECT COUNT(*) AS total FROM "users"');
        const totalParticipants = parseInt(totalParticipantsRows.rows[0].total); // Parse string to integer

        const results = (await pool.query(`
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
        `)).rows;

        const questionCountRows = await pool.query('SELECT COUNT(id) as total FROM "questions"');
        const totalQuestions = parseInt(questionCountRows.rows[0].total); // Parse string to integer
        
        res.json({
            totalParticipants: totalParticipants,
            totalQuestions: totalQuestions,
            results: results
        });
    } catch (error) {
        console.error('Error fetching admin metrics:', error);
        res.status(500).json({ message: 'Server error fetching admin metrics.' });
    }
});

// Admin Question Management (CRUD)
app.get('/admin/questions', isLoggedIn, isAdmin, async (req, res) => {
    try {
        const questions = (await pool.query('SELECT * FROM "questions" ORDER BY id DESC')).rows;
        res.json(questions);
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({ message: 'Server error fetching questions.' });
    }
});

app.post('/admin/questions', isLoggedIn, isAdmin, async (req, res) => {
    const { questionText, optionA, optionB, optionC, optionD, correctOption } = req.body;

    if (!questionText || !optionA || !optionB || !optionC || !optionD || !correctOption) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        // 1. Check for duplicate question text
        const duplicateCheck = await pool.query('SELECT id FROM "questions" WHERE "question_text" = $1', [questionText]);
        if (duplicateCheck.rows.length > 0) {
            return res.status(409).json({ message: 'A question with this exact text already exists.' });
        }
        
        // 2. Insert new question
        await pool.query(
            'INSERT INTO "questions" ("question_text", "option_a", "option_b", "option_c", "option_d", "correct_option") VALUES ($1, $2, $3, $4, $5, $6)',
            [questionText, optionA, optionB, optionC, optionD, correctOption]
        );
        res.status(201).json({ message: 'Question added successfully.' });
    } catch (error) {
        console.error('Error adding question:', error);
        res.status(500).json({ message: 'Server error adding question.' });
    }
});

app.delete('/admin/questions/:id', isLoggedIn, isAdmin, async (req, res) => {
    const questionId = req.params.id;

    try {
        await pool.query('DELETE FROM "questions" WHERE id = $1', [questionId]);
        res.json({ message: 'Question deleted successfully.' });
    } catch (error) {
        console.error('Error deleting question:', error);
        res.status(500).json({ message: 'Server error deleting question.' });
    }
});

// --- STUDENT QUIZ ROUTES ---

app.post('/student/start-quiz', isLoggedIn, async (req, res) => {
    const userId = req.userId;
    const QUIZ_LENGTH = 10;

    try {
        const userStatusResult = await pool.query("SELECT quiz_status FROM \"users\" WHERE id = $1", [userId]);
        const userStatus = userStatusResult.rows[0].quiz_status;

        if (userStatus === 'completed' || userStatus === 'disqualified') {
            return res.status(403).json({ message: 'Access denied. You have already completed or been disqualified from the quiz.' });
        }
        
        const activeAttempts = await pool.query("SELECT id FROM \"attempts\" WHERE user_id = $1 AND status = 'started'", [userId]);
        if (activeAttempts.rows.length > 0) {
            return res.status(409).json({ message: 'Quiz already in progress. Please finish your existing attempt.' });
        }

        const allQuestionsResult = await pool.query('SELECT id FROM "questions"');
        const allQuestions = allQuestionsResult.rows;
        
        if (allQuestions.length < QUIZ_LENGTH) {
            return res.status(400).json({ message: `Need at least ${QUIZ_LENGTH} questions to start the quiz.` });
        }

        const shuffledIds = allQuestions.map(q => q.id).sort(() => 0.5 - Math.random());
        const questionIds = shuffledIds.slice(0, QUIZ_LENGTH);

        const startTime = new Date().toISOString();
        const shuffledQuestionsJson = JSON.stringify(questionIds);
        
        // Update user status to 'started' and insert attempt
        await pool.query('UPDATE "users" SET quiz_status = $1 WHERE id = $2', ['started', userId]);
        
        const result = await pool.query(
            'INSERT INTO "attempts" ("user_id", "shuffled_questions", "status", "score") VALUES ($1, $2, $3, $4) RETURNING id',
            [userId, shuffledQuestionsJson, 'started', null]
        );

        res.json({
            message: 'Quiz started!',
            attemptId: result.rows[0].id,
            questionIds: questionIds,
            startTime: startTime
        });
    } catch (error) {
        console.error('Error starting quiz:', error);
        res.status(500).json({ message: 'Server error occurred while starting the quiz.' });
    }
});

// Route to fetch the actual question content for the quiz
app.get('/questions', isLoggedIn, async (req, res) => {
    const { ids } = req.query; 

    if (!ids) {
        return res.status(400).json({ message: 'Missing question IDs.' });
    }

    const idArray = ids.split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id));

    if (idArray.length === 0) {
        return res.status(400).json({ message: 'Invalid question IDs provided.' });
    }
    
    // Convert IDs into a format for PostgreSQL's IN clause
    const placeholders = idArray.map((_, i) => `$${i + 1}`).join(',');
    const query = `SELECT id, question_text, option_a, option_b, option_c, option_d FROM "questions" WHERE id IN (${placeholders})`;

    try {
        const questionsResult = await pool.query(query, idArray);
        const questions = questionsResult.rows;
        
        // Sort the questions based on the order of IDs in the original request
        const orderedQuestions = idArray.map(id => questions.find(q => q.id === id));
        
        res.json(orderedQuestions.filter(q => q));
    } catch (error) {
        console.error('Error fetching questions by IDs:', error);
        res.status(500).json({ message: 'Server error fetching question details.' });
    }
});


app.post('/student/submit-answers', isLoggedIn, async (req, res) => {
    const userId = req.userId;
    const { attemptId, answers, isCheating } = req.body; 
    const endTime = new Date();

    if (!attemptId || !answers) {
        return res.status(400).json({ message: 'Missing attempt ID or answers.' });
    }

    try {
        // 1. Get the current attempt and the list of question IDs
        const attemptRows = await pool.query('SELECT shuffled_questions FROM "attempts" WHERE id = $1 AND user_id = $2 AND status = $3', [attemptId, userId, 'started']);

        if (attemptRows.rows.length === 0) {
            // Check if it's already completed and return a special status
            const completedRows = await pool.query('SELECT score FROM "attempts" WHERE id = $1 AND user_id = $2 AND status = $3', [attemptId, userId, 'completed']);
            if (completedRows.rows.length > 0) {
                return res.status(200).json({ message: 'Quiz already submitted.', score: completedRows.rows[0].score, totalQuestions: 10 });
            }
            return res.status(404).json({ message: 'Active quiz attempt not found or invalid user.' });
        }
        
        // PostgreSQL returns JSON/JSONB fields as JavaScript objects
        const questionIds = attemptRows.rows[0].shuffled_questions;
        
        // 2. Fetch the correct answers for all questions in the quiz
        const placeholders = questionIds.map((_, i) => `$${i + 1}`).join(',');
        const correctAnswersResult = await pool.query(`SELECT id, correct_option FROM "questions" WHERE id IN (${placeholders})`, questionIds);
        const correctAnswers = correctAnswersResult.rows;

        const correctAnswersMap = correctAnswers.reduce((map, q) => {
            if (q.correct_option) {
                map[q.id] = q.correct_option;
            } else {
                console.warn(`Question ID ${q.id} has a NULL correct_option. Skipping.`);
            }
            return map;
        }, {});

        // 3. Calculate Score
        let score = 0;
        for (const qId of questionIds) {
            const userAnswer = answers[qId];
            const correctOption = correctAnswersMap[qId];

            if (userAnswer && correctOption && userAnswer === correctOption) {
                score++;
            }
        }
        
        // Determine final quiz status
        const finalQuizStatus = isCheating ? 'disqualified' : 'completed';

        // 4. Update the attempt record and permanently lock the user
        await pool.query(
            'UPDATE "attempts" SET status = $1, score = $2, end_time = $3 WHERE id = $4',
            ['completed', score, endTime, attemptId]
        );
        
        await pool.query('UPDATE "users" SET quiz_status = $1 WHERE id = $2', [finalQuizStatus, userId]);

        res.json({
            message: 'Quiz submitted successfully!',
            score: score,
            totalQuestions: questionIds.length,
            status: finalQuizStatus
        });
    } catch (error) {
        console.error('Error submitting quiz:', error);
        res.status(500).json({ message: 'Server error occurred while submitting the quiz.' });
    }
});

// --- LEADERBOARD API ROUTE ---

app.get('/leaderboard-data', isLoggedIn, async (req, res) => {
    try {
        const topScores = (await pool.query(`
            SELECT 
                u.full_name, 
                a.score, 
                a.created_at
            FROM "attempts" a
            JOIN "users" u ON a.user_id = u.id
            WHERE a.status = 'completed' AND u.quiz_status != 'disqualified'
            ORDER BY a.score DESC, a.end_time ASC
            LIMIT 10
        `)).rows;

        res.json(topScores);
    } catch (error) {
        console.error('Error fetching leaderboard:', error);
        res.status(500).json({ message: 'Server error fetching leaderboard data.' });
    }
});


// --- Serve General HTML Files (MUST use path.join and be before file serving) ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/admin.html', isLoggedIn, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});
app.get('/student.html', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'student.html'));
});
app.get('/leaderboard.html', isLoggedIn, (req, res) => {
    res.sendFile(path.join(__dirname, 'leaderboard.html'));
});


// --- Server Start ---
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log(`Open http://localhost:${port}/ in your browser to test.`);
});
