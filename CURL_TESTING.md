# Curl Commands for Proxy SIEM Testing

## Legitimate Requests
```bash
curl -X GET http://localhost:3000/test
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"testpass\"}"
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\": \"testuser\", \"password\": \"wrongpassword\"}"
```

## SQL Injection Tests
```bash
curl -X GET "http://localhost:3000/search?q=%27%20OR%201%3D1%20--"
curl -X GET "http://localhost:3000/users?id=1%20UNION%20SELECT%20*%20FROM%20passwords"
curl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\": \"testuser'; DROP TABLE users; --\", \"password\": \"testpass\"}"
```

## Directory Traversal Tests
```bash
curl -X GET "http://localhost:3000/file?path=../../../etc/passwd"
curl -X GET "http://localhost:3000/download?file=..\\..\\windows\\system32\\config\\sam"
curl -X GET "http://localhost:3000/assets?file=%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"
```

## XSS Tests
```bash
curl -X GET "http://localhost:3000/search?q=%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E"
curl -X GET "http://localhost:3000/redirect?url=javascript%3Aalert%28%22XSS%22%29"
curl -X POST http://localhost:3000/comment -H "Content-Type: application/json" -d "{\"comment\": \"<img src=x onerror=alert('XSS')>\"}"
```

## Rate Limiting Tests
```bash
# General rate limit (15 requests)
for i in {1..15}; do curl -s -X GET http://localhost:3000/test; echo "Request $i"; done

# Login rate limit (8 attempts)  
for i in {1..5}; do curl -s -X POST http://localhost:3000/login -H "Content-Type: application/json" -d "{\"username\": \"hacker\", \"password\": \"wrongpassword\"}"; echo "Login $i"; done
```

## Escalation Test
```bash
# Trigger multiple attack types
for i in {1..12}; do curl -s -X GET http://localhost:3000/test; echo "Rate $i"; done
curl -X GET "http://localhost:3000/search?q=%27%20OR%201%3D1%20--"
curl -X GET "http://localhost:3000/file?path=../../../etc/passwd"
```

## Log Access
```bash
curl -X GET http://localhost:3000/logs/security-critical.log/read
curl -X GET http://localhost:3000/logs/security-high.log/read
curl -X GET http://localhost:3000/logs/security-medium.log/read
``` 