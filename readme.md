# HTTP Security Proxy - Thought Process

## Problem Analysis & Approach

I used an LLM bouncing strategy (Gemini → Claude → Gemini) to better understand the problem domain and create a comprehensive approach. This helped me identify that the core challenge isn't building HTTP infrastructure, but designing effective security detection logic, helped me further understand the problem and its requirements, and brainstorm possible solutions.

**Mission:** Build an HTTP reverse proxy from scratch in Node.js that inspects incoming traffic and blocks specific threats (SQL injection, directory traversal, brute-force attacks). Focus on simplicity, practical utility, and performance.

---

## Key Architectural Decision: Express vs Raw HTTP

<details>
<summary><strong>Decision Process</strong> (Click to expand)</summary>

**Q: Express vs Raw HTTP - What's the right approach for this assignment?**
- **Initial Thought:** Raw HTTP would be more educational for learning proxy fundamentals
- **Context:** Re-reading the prompt: "Libraries for HTTP functionality are permitted" 
- **Realization:** The assignment focus is on security detection logic, not reinventing HTTP server fundamentals
- **Decision:** Use Express for both target server and reverse proxy implementation

**Why Express Won:**
- Middleware architecture ideal for security heuristic chain (SQL injection → brute-force → etc.)
- Can use `http-proxy-middleware` for actual proxying logic
- Lets me focus time on the core problem: designing security detection algorithms
- Request object can be annotated with security flags as it passes through middleware
- No need to write boilerplate HTTP parsing/routing code

</details>

---

## System Architecture

### Components
- **Proxy Server:** Core application listening on port 8080, forwards valid traffic
- **Target Server:** Minimal Node.js server on port 3000 with test endpoints (`GET /`, `POST /login`)
- **Test Client:** curl commands to simulate legitimate, suspicious, and malicious traffic

### Traffic Flow
```
Client Request → Proxy Server → Security Analysis → Target Server
                      ↓
               [Block if malicious]
                      ↓
Client Response ← Proxy Server ← Target Server Response
```

---

## Security Design Decisions

### IP Address Trust for Rate Limiting
**Decision:** Use direct socket IP address rather than trusting headers like `X-Forwarded-For`

**Reasoning:** While `X-Forwarded-For` headers provide the "real" client IP behind proxies/load balancers, they can be easily spoofed by malicious actors. For this security-focused implementation, I prioritize reliability over convenience.

**Trade-off:** May incorrectly rate-limit legitimate users behind shared proxies or NAT, but prevents attackers from bypassing rate limiting through header manipulation.

### Security Heuristics Strategy

| Heuristic Type | Detection Method | Response | State Required |
|----------------|------------------|----------|----------------|
| SQL Injection | Regex pattern matching in URL/body | Block with 403 | No |
| Directory Traversal | Path traversal pattern detection | Block with 403 | No |
| Brute Force | Failed login attempt tracking | Block subsequent requests | Yes |

**Key Insight:** Separating stateless (SQL injection, directory traversal) from stateful (brute-force) heuristics allows for different optimization strategies and cleaner code organization.

---

## Development Strategy

**Phase 1:** Basic forwarding proxy with proper HTTP header handling (hop-by-hop header removal, error handling)
**Phase 2:** Configuration and logging infrastructure  
**Phase 3:** Stateless security checks (regex-based detection)
**Phase 4:** Stateful security (brute-force tracking with memory management)
**Phase 5:** Containerization and documentation

**Strategic Decision:** Build incrementally to validate each layer works before adding complexity. This approach caught several edge cases early (header handling, memory cleanup) that would have been harder to debug in a monolithic implementation.

---

## Key Trade-offs & Limitations

**Security Detection:**
- Regex-based detection may miss obfuscated payloads, but provides good coverage for common attacks with minimal performance impact
- Brute-force detection vulnerable to distributed attacks from IP pools, but effective against single-source attacks

**Performance & Scalability:**
- Request body buffering for inspection could be problematic with large payloads
- In-memory state doesn't persist across restarts or scale across instances
- Synchronous security checks prioritize simplicity over high-throughput performance

**Design Philosophy:** These limitations are acceptable for a learning project focused on understanding proxy fundamentals and security heuristics. Production deployment would require streaming parsers, distributed state management, and async processing.

---

*This implementation prioritizes learning proxy fundamentals and security detection logic over production-ready robustness.*