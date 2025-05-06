const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 5001;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));

const users = [
    {
        username: 'testuser',
        // password123
        passwordHash: '$2b$10$WzIkqXo8Z9vTi/NnkG1JreBX0I36xlKM4IZM/7Xt2dzRBsKU7rLkC' 
    }
];

// login route
app.post('/login', async (req, res) => {
    // extract the username and password from request body
    const { username, password } = req.body;
    
    // search for users in the array in Server.js 
    const user = users.find(u => u.username === username);

    // If  not found, return 401 
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // make sure it matches the password hash
    const validPassword = await bcrypt.compare(password, user.passwordHash);
    
    // If doesn't match, return 401 
    if (!validPassword) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // If valid, send success response
    res.json({ message: 'success' });
});

// Start the server and listen on specified port
// listening referes to the proocess of waiting for network requests on a specific port
// The example is 'having a doorman who watches a specific door (port) for visitors (requests)'

// opens a port for the server to listen and starts accepting requests
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});