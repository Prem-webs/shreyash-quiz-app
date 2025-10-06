const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables from .env file
dotenv.config();

// --- Variable Initialization ---
const app = express();
const port = 3000;

// --- MySQL Connection Pool Setup ---
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'prem', // **Ensure this is your correct password!**
    database: process.env.DB_NAME || 'quiz_competition',
    // Critical connection settings for robustness
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    insecureAuth: true 
});

// --- Simple Session Storage (In-Memory) ---
const sessions = {}; // sessionId -> { userId, role, expiration }

// --- Middleware setup ---
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Helper function to check login status
const isLoggedIn = (req, res, next) => {
    const sessionId = req.headers['x-session-id'] || req.query.sessionId;

    if (!sessionId || !sessions[sessionId]) {
        // Redirect to login page for HTML files, respond with 401 for API calls
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
        const connection = await pool.getConnection();
        connection.release();
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
    const role = 'student'; // All general registrations are students

    if (!fullName || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        const passwordHash = await bcrypt.hash(password, 10);
        // Insert new user, setting default quiz_status
        await pool.query('INSERT INTO users (full_name, email, password_hash, role, quiz_status) VALUES (?, ?, ?, ?, ?)', 
            [fullName, email, passwordHash, role, 'unattempted']);
        res.status(201).json({ message: 'Registration successful. Please log in.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'This email is already registered.' });
        }
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    console.log(`[LOGIN DEBUG] Attempt for: ${email}`); // Debug log

    try {
        // Fetch user data including the new quiz_status
        const [rows] = await pool.query('SELECT id, password_hash, role, quiz_status FROM users WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) {
            console.log(`[LOGIN DEBUG] DB Hash fetched: User not found`); // Debug log
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        
        // --- Lockout Check Bypass (Admin) ---
        if (user.role === 'student') {
             // --- Student Lockout Check ---
            if (user.quiz_status === 'completed' || user.quiz_status === 'disqualified') {
                return res.status(403).json({ message: 'Access denied. You have already completed or been disqualified from the quiz.' });
            }
        }
        // --- End Lockout Check ---

        console.log(`[LOGIN DEBUG] DB Hash fetched: ${user.password_hash}`); // Debug log
        
        const match = await bcrypt.compare(password, user.password_hash);
        
        console.log(`[LOGIN DEBUG] Password match result: ${match}`); // Debug log

        if (match) {
            const sessionId = `s${user.id}_${Date.now()}`;
            sessions[sessionId] = { userId: user.id, role: user.role, expiration: Date.now() + 3600000 }; // 1 hour
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
        const [totalParticipantsRows] = await pool.query('SELECT COUNT(id) as total FROM users');
        const totalParticipants = totalParticipantsRows[0].total;

        const [results] = await pool.query(`
            SELECT 
                u.full_name, 
                u.email,
                a.score, 
                a.created_at,
                a.end_time
            FROM attempts a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'completed'
            ORDER BY a.score DESC, a.end_time ASC
        `);

        // Get total number of questions for context
        const [questionCountRows] = await pool.query('SELECT COUNT(id) as total FROM questions');
        const totalQuestions = questionCountRows[0].total;
        
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
        const [questions] = await pool.query('SELECT * FROM questions ORDER BY id DESC');
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
        await pool.query(
            'INSERT INTO questions (question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?, ?, ?, ?, ?, ?)',
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
        await pool.query('DELETE FROM questions WHERE id = ?', [questionId]);
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
        // --- Student Lockout Check (Prevent starting if already completed/disqualified) ---
        const [userStatusRows] = await pool.query("SELECT quiz_status FROM users WHERE id = ?", [userId]);
        const userStatus = userStatusRows[0].quiz_status;

        if (userStatus === 'completed' || userStatus === 'disqualified') {
            return res.status(403).json({ message: 'Access denied. You have already completed or been disqualified from the quiz.' });
        }
        // --- End Student Lockout Check ---
        
        // --- ANTI-CHEATING ACTIVATED: Check for active attempt ---
        const [activeAttempts] = await pool.query("SELECT id FROM attempts WHERE user_id = ? AND status = 'started'", [userId]);
        if (activeAttempts.length > 0) {
            // User is already in a test session and cannot start a new one
            return res.status(409).json({ message: 'Quiz already in progress. Please finish your existing attempt.' });
        }
        // --- END ANTI-CHEATING CHECK ---

        const [allQuestions] = await pool.query('SELECT id FROM questions');
        
        if (allQuestions.length < QUIZ_LENGTH) {
            return res.status(400).json({ message: `Need at least ${QUIZ_LENGTH} questions to start the quiz.` });
        }

        // Shuffle and select the first 10 question IDs
        const shuffledIds = allQuestions.map(q => q.id).sort(() => 0.5 - Math.random());
        const questionIds = shuffledIds.slice(0, QUIZ_LENGTH);

        const startTime = new Date().toISOString();
        const shuffledQuestionsJson = JSON.stringify(questionIds);
        
        // Update user status to 'started' and insert attempt
        await pool.query('UPDATE users SET quiz_status = ? WHERE id = ?', ['started', userId]);
        
        const [result] = await pool.query(
            'INSERT INTO attempts (user_id, shuffled_questions, status, score) VALUES (?, ?, ?, NULL)',
            [userId, shuffledQuestionsJson, 'started']
        );

        res.json({
            message: 'Quiz started!',
            attemptId: result.insertId,
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
    
    // Construct the query with proper placeholders
    const placeholders = idArray.map(() => '?').join(',');
    const query = `SELECT id, question_text, option_a, option_b, option_c, option_d FROM questions WHERE id IN (${placeholders})`;

    try {
        const [questions] = await pool.query(query, idArray);
        
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
        const [attemptRows] = await pool.query('SELECT JSON_UNQUOTE(shuffled_questions) AS shuffled_questions_str FROM attempts WHERE id = ? AND user_id = ? AND status = "started"', [attemptId, userId]);

        if (attemptRows.length === 0) {
            // Check if it's already completed and return a special status
            const [completedRows] = await pool.query('SELECT score FROM attempts WHERE id = ? AND user_id = ? AND status = "completed"', [attemptId, userId]);
            if (completedRows.length > 0) {
                return res.status(200).json({ message: 'Quiz already submitted.', score: completedRows[0].score, totalQuestions: 10 });
            }
            return res.status(404).json({ message: 'Active quiz attempt not found or invalid user.' });
        }
        
        const questionIds = JSON.parse(attemptRows[0].shuffled_questions_str);
        
        // 2. Fetch the correct answers for all questions in the quiz
        const placeholders = questionIds.map(() => '?').join(',');
        const [correctAnswers] = await pool.query(`SELECT id, correct_option FROM questions WHERE id IN (${placeholders})`, questionIds);

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
            'UPDATE attempts SET status = "completed", score = ?, end_time = ? WHERE id = ?',
            [score, endTime, attemptId]
        );
        
        await pool.query('UPDATE users SET quiz_status = ? WHERE id = ?', [finalQuizStatus, userId]);

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
        const [topScores] = await pool.query(`
            SELECT 
                u.full_name, 
                a.score, 
                a.created_at
            FROM attempts a
            JOIN users u ON a.user_id = u.id
            WHERE a.status = 'completed' AND u.quiz_status != 'disqualified'
            ORDER BY a.score DESC, a.end_time ASC
            LIMIT 10
        `);

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