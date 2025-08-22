#Proxy SIEM - Docker Setup

## Quick Start

1. **Build the Docker image:**
   ```bash
   docker build -t proxy-siem .
   ```

2. **Run the application:**
   ```bash
   docker run -p 3000:3000 -p 3001:3001 proxy-siem
   ```

3. **Access the test client:**
   Open your browser to: `http://localhost:3000`

## What's Running

- **Port 3000:** Proxy server with test client interface
- **Port 3001:** Target backend server
- **Logs:** Security events logged to `/app/logs/` inside container

## Testing the SIEM

1. Navigate to `http://localhost:3000`
2. Use the test buttons to simulate attacks:
   - **Green buttons:** Legitimate requests
   - **Yellow buttons:** Rate limiting tests  
   - **Red buttons:** Malicious attacks (SQL injection, XSS, etc.)
3. Click "Read Log" to view security events
4. Monitor console output for real-time security alerts

## Stopping

```bash
docker stop <container-id>
```

## Architecture

```
Browser → Proxy (3000) → Security Analysis → Target Server (3001)
                ↓
        [Logs security events]
``` 