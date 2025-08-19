Thought process and problem solving routes:
______________________________________________

I am going to supply the problem domain to a LLM to get a better understanding of the problem. I Will bounce the output from 1 LLM to another, and then back (Gemini, to claude, back to gemini) Which has helped me created the tasklist below:

**Mission:** We are building an HTTP reverse proxy from scratch in Node.js. The primary goal is to learn the fundamentals of proxies, network requests, and basic security heuristics. The final product will be a simple, efficient, and well-documented application that inspects incoming HTTP traffic, identifies specific threats, and blocks them.

---

<details>
<summary><strong>Brainstorming & Rubber Ducking Log</strong> (Click to expand)</summary>

*A running log of important questions, realizations, and architectural decisions made during development.*

---

**Q: Express vs Raw HTTP - What should I use for the reverse proxy?**
- **Context:** Originally planned raw HTTP module, but considered Express for easier development, I believe that the task primary focus is on the proxy and the detection methods used in the proxy rather than the server itself so i will offload this all to express.
- **Realization:** Need to distinguish between target server (testing) vs actual proxy (learning objective)  
- **Decision:** Express for target server simulation, raw HTTP for reverse proxy implementation
- **Why:** Want maximum control and visibility into HTTP internals for anomaly detection. No point abstracting away the information and learning opportunity (I might just lean into express but will try to do it raw first...).

---

</details>

---

## Rules of Engagement

This project is for learning. The following principles must be followed:

1. **Guide, Don't Solve:** Do not generate complete functions or files. Provide explanations, conceptual outlines, and suggestions for which Node.js modules or APIs to use. I will write all the final code.
2. **Explain the "Why":** For every recommendation (e.g., using a specific data structure or function), explain *why* it's the right choice and what the potential trade-offs are.
3. **One Step at a Time:** We will follow the development plan phase by phase. Do not jump ahead.
4. **Fundamentals First:** We will use Node.js's built-in `http` module for the core proxy logic instead of high-level proxy libraries. This is crucial for my understanding.

---

## Architectural Blueprint

Our system will consist of three parts:

### Components

- **The Proxy Server:** The core application we are building. It will listen on one port (e.g., `8080`) and forward valid traffic to the target server.
- **The Simulated Target Server:** A separate, minimal Node.js `http` server that will act as the "Web Server." It will listen on a different port (e.g., `3000`) and have just two endpoints for testing:
  - `GET /`: Responds with `200 OK`.
  - `POST /login`: Always responds with `401 Unauthorized`.
- **The Test Client (curl):** A command-line tool used to simulate legitimate, suspicious, and malicious client traffic to validate the proxy's functionality.

### Project Structure

```
/http-security-proxy
├── index.js         // Entry point: loads config, starts the proxy server.
├── proxy.js         // Core logic for forwarding requests and responses.
├── security.js      // Logic for all attack detection heuristics.
├── logger.js        // Simple module for formatted console logging.
├── config.json      // Configuration for ports, target URL, and security rules.
└── Dockerfile       // To containerize the final application.
```

### Traffic Flow

```
Client Request → Proxy Server → Security Analysis → Target Server
                      ↓
               [Block if malicious]
                      ↓
Client Response ← Proxy Server ← Target Server Response
```

---

## Phased Development Plan

We will build the proxy in logical, incremental stages.

### Phase 1: The Basic Forwarding Proxy

**Goal:** Create a proxy that transparently forwards all traffic.

**Tasks:**
1. Set up the `proxy.js` file using `http.createServer` to listen for requests.
2. For each incoming request, use `http.request` to create a new request to the target server.
3. Use streams (`req.pipe(proxyReq)` and `proxyRes.pipe(res)`) to efficiently pass the request body and response body without buffering.
4. Ensure headers, method, and URL path are correctly passed.
5. **HTTP Header Handling:** Identify and remove hop-by-hop headers (such as `Connection`, `Keep-Alive`, `Proxy-Authenticate`) before forwarding the request to the target server. These headers are meant only for the immediate connection and should not be forwarded.
6. **Robust Error Handling:** Handle network errors gracefully. When the proxy fails to connect to the target server, it shouldn't crash. Instead, it should return a `502 Bad Gateway` error to the original client, demonstrating foresight into real-world operational issues.

### Phase 2: Configuration & Logging

**Goal:** Make the proxy configurable and add visibility into its operations.

**Tasks:**
1. Create `config.json` to manage ports and the target server URL.
2. Implement `logger.js` to log every incoming request and its source IP.

### Phase 3: Stateless Security Heuristics (SQLi & Directory Traversal)

**Goal:** Implement security checks that analyze the content of a single request.

**Tasks:**
1. In `security.js`, create a function to detect SQL injection patterns (e.g., `OR 1=1`, `--`) in the URL query and request body using regular expressions.
2. Create a second function to detect Directory Traversal patterns (e.g., `../`, `..%2F`).
3. Integrate these checks into `proxy.js`. If a threat is detected, log the event and immediately respond to the client with a `403 Forbidden` error without forwarding the request.

### Phase 4: Stateful Security Heuristic (Brute-Force)

**Goal:** Implement a security check that requires memory of past events.

**Tasks:**
1. Design the data structure for tracking failed login attempts (a `Map` where the key is the IP and the value is an object like `{ count, windowStart }`).
2. In `proxy.js`, after receiving a response from the target server, check if it's a `401` from the `/login` endpoint.
3. If it is, update the state in the brute-force detection logic in `security.js`.
4. Implement the blocking logic: if an IP exceeds the configured threshold, block all subsequent requests from it.
5. **Memory Management:** Implement a cleanup mechanism to prevent memory leaks. Use `setInterval` to periodically remove entries from the tracking Map where `windowStart` is older than a defined threshold (e.g., more than an hour old). This ensures long-term application stability.

### Phase 5: Finalization (Docker & README)

**Goal:** Prepare the project for submission.

**Tasks:**
1. Write a simple, efficient `Dockerfile` to run the proxy.
2. Create a detailed `README.md` file that explains:
   - The project's purpose.
   - The design decisions made.
   - How to run the application using Docker.
   - Specific `curl` commands to test and demonstrate that each of the three security heuristics is working correctly.
   - **Design Decisions:** Document key architectural choices, including the decision to use the request's direct socket IP address for rate-limiting rather than trusting headers like `X-Forwarded-For`, and explain the reasoning behind this choice.
   - **Limitations:** Include a comprehensive section acknowledging the solution's trade-offs and potential vulnerabilities.

---

## Design Decisions

### IP Address Trust for Rate Limiting

For brute-force detection, this proxy uses the direct socket IP address from the incoming connection rather than trusting headers like `X-Forwarded-For`. 

**Reasoning:** While `X-Forwarded-For` headers can provide the "real" client IP when clients are behind proxies or load balancers, they can also be easily spoofed by malicious actors. For this security-focused implementation, we prioritize reliability over convenience by using only the direct connection IP.

**Trade-off:** This approach may incorrectly rate-limit legitimate users behind shared proxies or NAT, but it prevents attackers from bypassing rate limiting through header manipulation.

---

## Security Heuristics Overview

| Heuristic Type | Detection Method | Response |
|----------------|------------------|----------|
| SQL Injection | Pattern matching in URL/body | Block with 403 |
| Directory Traversal | Path traversal pattern detection | Block with 403 |
| Brute Force | Failed login attempt tracking | Block subsequent requests |

---

## Known Limitations

This implementation prioritizes learning and simplicity over production-ready robustness. Key limitations include:

### Security Detection Limitations
- **Regex-based Detection:** The security heuristics use regular expression pattern matching, which may not catch all possible attack variations, especially heavily obfuscated or encoded payloads.
- **Evasion Techniques:** Sophisticated attackers could potentially bypass detection through various encoding schemes, case variations, or novel attack vectors not covered by the current patterns.

### Brute-Force Protection Limitations
- **IP Pool Attacks:** The brute-force detector could be bypassed if an attacker uses a large pool of different IP addresses to distribute login attempts.
- **Legitimate User Impact:** Users behind shared proxies or NAT devices may be incorrectly blocked due to the actions of other users sharing the same IP address.

### Performance and Scalability Limitations
- **Request Body Buffering:** Request bodies are read into memory buffers for inspection, which could be problematic with extremely large payloads and may present a denial-of-service vulnerability.
- **In-Memory State:** The brute-force tracking uses an in-memory Map, which doesn't persist across application restarts and won't scale across multiple proxy instances.
- **Synchronous Processing:** Security checks are performed synchronously, which could impact response times under high load.

### HTTP Protocol Limitations
- **Limited HTTP Feature Support:** This implementation focuses on basic HTTP/1.1 functionality and doesn't handle advanced features like HTTP/2, WebSockets, or complex authentication schemes.
- **Header Handling:** While hop-by-hop headers are filtered, other nuanced header transformations that production proxies handle are not implemented.

### Operational Limitations
- **No Persistence:** All state (brute-force tracking, logs) is lost on application restart.
- **Basic Error Handling:** Error scenarios beyond basic network failures may not be handled gracefully.
- **No Configuration Reloading:** Configuration changes require application restart.

**Note:** These limitations are acceptable for a learning project but would need to be addressed in a production environment through techniques like streaming parsers, distributed state management, advanced pattern matching, and comprehensive error handling.