'use strict';
const express = require('express');
const http = require('http');
const path = require('path');

const { RequestValidated } = require('./security');

const PORT = 3000;
const app = express();
const host = 'localhost';

// Parse JSON and URL-encoded bodies consistently with target server
app.use(express.json({limit: '10mb'}));
app.use(express.urlencoded({extended: true}));

//I chose root-level static serving for cleaner URLs, but I had to implement bypass logic in my security middleware. 
// In hindsight, using a /static prefix would eliminate the need for bypasses and create cleaner separation between 
// static assets and API endpoints... current approach creates a potential security vulnerability where attackers
// could bypass validation by appending file extensions to malicious requests.
app.use(express.static(path.join(__dirname, '../test-client')));

//read the logs from the logs folder for the front end to display
app.get('/logs/:filename/read', (req, res) => {
    const filename = req.params.filename;
    const allowedFiles = ['security-critical.log', 'security-high.log', 'security-medium.log'];
    
    if (!allowedFiles.includes(filename)) {
        return res.status(404).json({ error: 'Log file not found' });
    }
    
    const logPath = path.join(__dirname, '../logs', filename);
    const fs = require('fs');
    
    if (!fs.existsSync(logPath)) {
        return res.status(404).json({ error: 'Log file does not exist' });
    }
    
    try {
        const logContent = fs.readFileSync(logPath, 'utf8');
        res.json({ 
            filename: filename,
            content: logContent,
            size: logContent.length 
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to read log file' });
    }
});

app.use((req, res, next) => {
    // Skip security validation only for static assets
    if (req.path.match(/\.(css|js|html|png|jpg|ico)$/)) {
        return next();
    }
    
    // All other requests must pass security validation
    const validationResult = RequestValidated(req);
    if (validationResult.valid) {
        next();
    } else {
        let message;
        switch (validationResult.reason) {
            case 'security_threat':
                message = 'Forbidden - Security threat detected (SQL injection, XSS, or directory traversal)';
                break;
            case 'rate_limited':
                message = 'Forbidden - Rate limit exceeded. Too many requests within the time window.';
                break;
            case 'malformed':
                message = 'Bad Request - Malformed request data';
                break;
            default:
                message = 'Forbidden';
        }
        res.status(403).send(message);
    }
});


// Proxy ALL requests to backend server (after security validation)
app.use((req, res) => {
    //phone number
    const proxyOptions = {
        host: host,
        port: 3001,
        path: req.url,
        method: req.method,
        headers: req.headers
    }
    //phone call
    const proxy = http.request(proxyOptions, (proxyResponse) => {
        res.writeHead(proxyResponse.statusCode, proxyResponse.headers);
        //we will just stream the data back to the client, if the proxy OK's the request then we send the data, end of story.
                proxyResponse.on('data', (chunk) => {
                    res.write(chunk);
                });
                proxyResponse.on('end', () => {
                    res.end();
                });
            }).on('error', (err) => {
                console.error('Proxy error:', err);
                res.status(502).send('Bad Gateway');
            });
            
            // Handle request body for different HTTP methods
            //this is a bit of a hack, but it works, I would like to improve this in the future.
            //need to handle no content type header and also handle no content length. 

            //would need to use raw middleware and stream piping to handle this better, to account for file uploads, xml payloads, and graphQL queries.
            if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
                if (req.body) {
                    // Send the parsed body as JSON
                    proxy.write(JSON.stringify(req.body));
                    proxy.end();
                } else {
                    // No body, just end the request
                    proxy.end();
                }
            } else {
                proxy.end();
            }
});

app.listen(PORT, () => {
    console.log(`Proxy server is running on port ${PORT}`);
});
