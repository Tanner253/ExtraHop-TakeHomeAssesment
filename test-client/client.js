// Simple Proxy SIEM Test Client
// AI GENERATED:
class ProxyTestClient {
    constructor() {
        this.baseUrl = 'http://localhost:3000';
        this.responseLog = document.getElementById('responseLog');
        this.flagCount = 0;
        this.detectedPatterns = new Set(); // Track which patterns have been detected once
    }

    // Log responses and update traffic light
    logResponse(testName, response, status, error = null) {
        const timestamp = new Date().toLocaleTimeString();
        
        // Flag once per pattern type detected
        if (status === 403) {
            let patternType = 'unknown';
            
            if (testName.includes('SQL Injection')) patternType = 'sql';
            else if (testName.includes('XSS')) patternType = 'xss';
            else if (testName.includes('Directory Traversal')) patternType = 'directory';
            else if (testName.includes('Login') && testName.includes('Rate')) patternType = 'login_rate';
            else if (testName.includes('Rate Limit')) patternType = 'general_rate';
            
            // Only increment flag once per pattern type
            if (!this.detectedPatterns.has(patternType)) {
                this.detectedPatterns.add(patternType);
                this.flagCount++;
                document.getElementById('flagCounter').textContent = this.flagCount;
                this.updateTrafficLight();
            }
        }
        
        if (response && response.includes('ESCALATED THREAT')) {
            this.setRedLight();
        }
        
        // Add log entry
        const logDiv = document.createElement('div');
        logDiv.className = 'log-entry';
        
        let statusClass = status >= 400 ? (status === 403 ? 'blocked' : 'error') : 'success';
        
        logDiv.innerHTML = `
            <div class="log-timestamp">[${timestamp}]</div>
            <div class="log-test-name">${testName}</div>
            <div class="log-status ${statusClass}">Status: ${status}</div>
            <div class="log-response">${error ? `Error: ${error}` : `Response: ${testName.includes('📖') ? response : response.substring(0, 200)}${!testName.includes('📖') && response.length > 200 ? '...' : ''}`}</div>
        `;
        
        this.responseLog.appendChild(logDiv);
        this.responseLog.scrollTop = this.responseLog.scrollHeight;
    }

    // Update traffic light based on flag count
    updateTrafficLight() {
        document.querySelectorAll('.light').forEach(light => light.classList.remove('active'));
        
        if (this.flagCount >= 2) {
            this.setRedLight();
        } else {
            document.getElementById('yellowLight').classList.add('active');
            document.getElementById('threatStatus').textContent = 'ELEVATED';
        }
    }

    // Set red light for critical threats
    setRedLight() {
        document.querySelectorAll('.light').forEach(light => light.classList.remove('active'));
        document.getElementById('redLight').classList.add('active');
        document.getElementById('threatStatus').textContent = 'CRITICAL';
    }

    // Make request to proxy
    async makeRequest(method, path, body = null, testName = '') {
        const button = event?.target;
        if (button) {
            button.classList.add('loading');
            button.disabled = true;
        }

        try {
            const options = { method, headers: { 'Content-Type': 'application/json' } };
            if (body) options.body = JSON.stringify(body);

            const response = await fetch(`${this.baseUrl}${path}`, options);
            const responseText = await response.text();
            
            this.logResponse(testName, responseText, response.status);
            
        } catch (error) {
            this.logResponse(testName, '', 0, error.message);
        } finally {
            if (button) {
                button.classList.remove('loading');
                button.disabled = false;
            }
        }
    }

    // Multiple requests helper
    async makeMultipleRequests(requestFunc, count, delay = 100) {
        for (let i = 0; i < count; i++) {
            await requestFunc();
            if (i < count - 1) await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

const client = new ProxyTestClient();

// Test functions
async function testLegitimateGet() {
    await client.makeRequest('GET', '/', null, 'Legitimate GET Request');
}

async function testLegitimateLogin() {
    await client.makeRequest('POST', '/login', { username: 'testuser', password: 'testpass' }, 'Valid Login Attempt');
}

async function testInvalidLogin() {
    await client.makeRequest('POST', '/login', { username: 'admin', password: 'wrongpassword' }, 'Invalid Login Attempt');
}

async function testSqlInjection1() {
    await client.makeRequest('GET', "/search?q=' OR 1=1 --", null, 'SQL Injection: OR 1=1');
}

async function testSqlInjection2() {
    await client.makeRequest('GET', "/users?id=1 UNION SELECT * FROM passwords", null, 'SQL Injection: UNION SELECT');
}

async function testSqlInjection3() {
    await client.makeRequest('POST', '/login', { username: "admin'; DROP TABLE users; --", password: "password" }, 'SQL Injection: DROP TABLE');
}

async function testDirectoryTraversal1() {
    await client.makeRequest('GET', '/file?path=../../../etc/passwd', null, 'Directory Traversal: etc/passwd');
}

async function testDirectoryTraversal2() {
    await client.makeRequest('GET', '/download?file=..\\..\\windows\\system32\\config\\sam', null, 'Directory Traversal: Windows System32');
}

async function testDirectoryTraversal3() {
    await client.makeRequest('GET', '/assets?file=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd', null, 'Directory Traversal: URL Encoded');
}

async function testXss1() {
    await client.makeRequest('GET', '/search?q=<script>alert("XSS")</script>', null, 'XSS: Script Tag');
}

async function testXss2() {
    await client.makeRequest('GET', '/redirect?url=javascript:alert("XSS")', null, 'XSS: JavaScript Protocol');
}

async function testXss3() {
    await client.makeRequest('POST', '/comment', { comment: '<img src="x" onerror="alert(\'XSS\')">' }, 'XSS: Event Handler');
}

async function testGeneralRateLimit() {
    const button = event.target;
    button.classList.add('loading');
    button.disabled = true;

    client.logResponse('General Rate Limit Test', 'Starting 15 rapid requests...', 200);
    
    try {
        await client.makeMultipleRequests(async () => {
            await client.makeRequest('GET', '/test', null, `General Rate Limit ${Date.now()}`);
        }, 15, 50);
    } finally {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

async function testLoginRateLimit() {
    const button = event.target;
    button.classList.add('loading');
    button.disabled = true;

    client.logResponse('Login Rate Limit Test', 'Starting 5 rapid login attempts...', 200);
    
    try {
        await client.makeMultipleRequests(async () => {
            await client.makeRequest('POST', '/login', { username: 'hacker', password: 'wrongpassword' }, `Login Brute Force ${Date.now()}`);
        }, 5, 100);
    } finally {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

async function testEscalation() {
    const button = event.target;
    button.classList.add('loading');
    button.disabled = true;

    client.logResponse('Escalation Test', 'Triggering multiple attack types to escalate to CRITICAL...', 200);
    
    try {
        await client.makeMultipleRequests(async () => {
            await client.makeRequest('GET', '/test', null, 'Escalation: Rate Limit');
        }, 12, 50);
        
        await client.makeRequest('GET', "/search?q=' OR 1=1 --", null, 'Escalation: SQL Injection');
        await client.makeRequest('GET', '/file?path=../../../etc/passwd', null, 'Escalation: Directory Traversal');
        
    } finally {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

async function testCombinedAttack() {
    const button = event.target;
    button.classList.add('loading');
    button.disabled = true;

    client.logResponse('Combined Attack Test', 'Launching multi-vector attack simulation...', 200);
    
    try {
        await client.makeRequest('GET', "/search?q=<script>alert('XSS')</script>' OR 1=1 --", null, 'Combined: SQL+XSS');
        
        await client.makeMultipleRequests(async () => {
            await client.makeRequest('GET', '/file?path=../../../etc/passwd', null, 'Combined: Traversal+Rate');
        }, 5, 100);
        
        await client.makeMultipleRequests(async () => {
            await client.makeRequest('POST', '/login', { username: "testuser'; DROP TABLE users; --", password: "testpass" }, 'Combined: Login+SQL');
        }, 3, 200);
        
    } finally {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

function clearLogs() {
    document.getElementById('responseLog').innerHTML = '';
    
    // Reset traffic light to green
    client.flagCount = 0;
    document.getElementById('flagCounter').textContent = '0';
    document.querySelectorAll('.light').forEach(light => light.classList.remove('active'));
    document.getElementById('greenLight').classList.add('active');
    document.getElementById('threatStatus').textContent = 'SECURE';
    
    client.logResponse('System', 'Response log cleared - Threat level reset', 200);
}

// Log reading modal functions
function showReadLogMenu() {
    document.getElementById('logModal').style.display = 'block';
}

function closeLogModal() {
    document.getElementById('logModal').style.display = 'none';
}

async function readLogFile(filename) {
    closeLogModal();
    
    try {
        const response = await fetch(`http://localhost:3000/logs/${filename}/read`);
        
        if (response.ok) {
            const logData = await response.json();
            const logContent = logData.content || 'Log file is empty';
            const fileSize = Math.round(logData.size / 1024);
            
            document.getElementById('responseLog').innerHTML = '';
            client.logResponse(`📖 ${filename}`, `File Size: ${fileSize}KB\n${'='.repeat(50)}\n${logContent}`, 200);
        } else {
            const errorData = await response.json();
            client.logResponse('Read Log Error', '', response.status, errorData.error);
        }
        
    } catch (error) {
        client.logResponse('Read Log Error', '', 0, error.message);
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('logModal');
    if (event.target === modal) {
        closeLogModal();
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    client.logResponse('System', 'Security Proxy SIEM Test Client Initialized\nReady to test security features...', 200);
}); 