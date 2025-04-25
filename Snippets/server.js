const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files from current directory

const users = [
  {
    username: 'testuser',
    passwordHash: '$2b$10$WzIkqXo8Z9vTi/NnkG1JreBX0I36xlKM4IZM/7Xt2dzRBsKU7rLkC' // password123
  }
];

// Login route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) {
    return res.status(401).json({ message: 'Invalid username or password' });
  }

  res.json({ message: 'success' });
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: 'Username already taken' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  users.push({ username, passwordHash });

  res.json({ message: 'User registered successfully' });
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
