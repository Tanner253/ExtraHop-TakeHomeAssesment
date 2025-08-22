'use strict';

const express = require('express');

const app = express();
const PORT = 3001;

//prevent huge payloads
app.use(express.json({limit: '10mb'}));


app.get('/', (req, res) => {
    res.send('✅ SUCCESS: Data received from backend server (port 3001) through proxy (port 3000) - Connection verified!');
});

app.get('/test', (req, res) => {
    res.send('Hello World - Web Server Resource');
});

app.post('/login', (req, res) => {
    if (!req.body) {
        return res.status(400).send('Request body required');
    }
    
    const { username, password } = req.body;
    if (username === 'testuser' && password === 'testpass') {
        res.send('Login successful');
    } else {
        res.status(401).send('Invalid credentials');
    }
});

app.use((err, req, res, next) => {
    if(err instanceof SyntaxError){
        return res.status(400).send('Invalid JSON');
    }
    next();
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
