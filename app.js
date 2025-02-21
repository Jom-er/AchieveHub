const express = require('express');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const session = require('express-session');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Session configuration
app.use(session({
  secret: 'your_secret_key',  // Replace with a strong secret
  resave: false,
  saveUninitialized: true
}));

// Set up MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',  // Replace with your actual password
  database: 'achievehub'
});

// Connect to MySQL
db.connect(err => {
  if (err) {
    console.error('Error connecting to the database: ' + err.stack);
    return;
  }
  console.log('Connected to the database');
});

// Sign-up Route
app.post('/signup', (req, res) => {
  const { username, password } = req.body;

  // Check if username already exists
  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(checkQuery, [username], (err, results) => {
    if (err) {
      return res.status(500).send('Error checking username');
    }
    
    if (results.length > 0) {
      return res.status(400).send('Username already taken');
    }

    // Hash password before saving to database
    bcrypt.hash(password, 10, (err, hashedPassword) => {
      if (err) {
        return res.status(500).send('Error hashing password');
      }

      // Insert new user into the database
      const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
      db.query(insertQuery, [username, hashedPassword], (err, result) => {
        if (err) {
          return res.status(500).send('Error inserting user');
        }
        res.status(200).send('User created successfully');
      });
    });
  });
});

// Login Route
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Fetch user data from the database
  const query = 'SELECT * FROM users WHERE username = ?';
  db.query(query, [username], (err, results) => {
    if (err) {
      return res.status(500).send('Database error');
    }

    if (results.length === 0) {
      return res.status(400).send('User not found');
    }

    // Compare the entered password with the hashed password
    bcrypt.compare(password, results[0].password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(400).send('Invalid credentials');
      }

      // Store user data in the session for authentication
      req.session.user = results[0];  // Store user info in session
      res.status(200).send('Logged in successfully');
    });
  });
});

// Logout Route (optional, to clear session)
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.status(200).send('Logged out successfully');
  });
});

// Run the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
