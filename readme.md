# HTTP Security Proxy - Thought Process

## Problem Analysis & Approach

I used an LLM bouncing strategy (Gemini → Claude → Gemini) to better understand the problem domain and create a comprehensive approach. This helped me identify that the core challenge isn't building HTTP infrastructure, but designing effective security detection logic, helped me further understand the problem and its requirements, and brainstorm possible solutions.

**Mission:** Build an HTTP reverse proxy from scratch in Node.js that inspects incoming traffic and blocks specific threats (SQL injection, directory traversal, brute-force attacks). Focus on simplicity, practical utility, and performance.

---
# TRUTHS
- 3 failed logins will trigger a log. HIGH
- 10 failed requests within timewindow will trigger a log. MEDIUM  
- sql detection will trigger a log. HIGH
- directory traversal will trigger a log. HIGH
- XSS will trigger a log. HIGH
- any 2 flags will trigger an escalation "CRITICAL"

## Key Architectural Decision: Manual Proxy Implementation

<details>
<summary><strong>Decision Process</strong> (Click to expand)</summary>

**Zero Trust Security Architecture Decision:**
- **Traditional Security:** Check for known threats → if none found, allow → Forward
- **Zero Trust (CHOSEN):** ALL security checks must pass → any failure = immediate deny
- **Why Zero Trust:** Proactive security posture, mirrors enterprise frameworks (Google BeyondCorp, AWS Zero Trust)
- **Implementation:** Security module returns boolean validation state, requests denied by default

**Security Module Architecture Decision:**
- **Options Considered:** Strategy Pattern, Builder Pattern, Simple Functional Approach
- **Decision:** Simple Functional Approach - `RequestValidated(req)` returns boolean
- **Why:** Readability first, maintainable, no over-engineering, appropriate complexity for scope
- **Structure:** `passesStatelessChecks(req) && passesStatefulChecks(req)`

</details>

---

## System Architecture

### Components
- **Proxy Server:** Core application listening on port 3000, forwards valid traffic
- **Target Server:** Minimal Node.js server on port 3001 with test endpoints (`GET /`, `POST /login`)
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

- instead of assuming requests are valid and checking for sus activities, we will assume all requests are sus and validate legitamate activities through thurough sniff tests:

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

## Implementation Summary

### Security Features Implemented

**Required:**
- **SQL Injection Detection** - Regex patterns detect common SQL attack vectors in URL, body, and headers
- **Brute Force Detection** - Sliding window rate limiting (10 requests/min general, 3 login attempts/3min)

**Additional Heuristics:**
- **Directory Traversal Detection** - Prevents unauthorized file system access (`../../../etc/passwd`)
- **Cross-Site Scripting (XSS) Detection** - Blocks malicious JavaScript injection attempts
- **Attack Escalation System** - CRITICAL logging when multiple attack types detected from same IP

**Architecture:**
- **Zero Trust Model** - All requests denied by default, must pass all security checks
- **Severity-Based Logging** - Machine-readable logs (CRITICAL/HIGH/MEDIUM/LOW) for SIEM integration
- **Transparent Proxying** - Forwards exact HTTP status codes, headers, and response bodies

---

## Technical Decisions & Trade-offs

### Performance vs Security
**Decision:** 90% accurate detection with fast regex patterns over 99% accurate detection with 10x performance cost.
**Rationale:** For high-volume traffic, speed matters. Can scale horizontally (load balancing) if needed.
**Trade-off:** Focused on common attack patterns rather than exotic evasion techniques.

### Zero Trust vs Performance
**Decision:** All requests undergo full security validation, no IP whitelisting.
**Rationale:** Prevents credential compromise and device masquerading attacks.
**Trade-off:** Higher CPU overhead per request, but maintains consistent security posture.

### Memory Management
**Decision:** Sliding window rate limiting with in-memory state storage.
**Rationale:** More accurate than reset windows, prevents timing-based evasion.
**Trade-off:** Memory usage grows with unique IP count. Cleanup needed for production (10-minute TTL recommended).
**Restart Behavior:** State loss on restart is acceptable - proxy downtime indicates larger infrastructure issues.

### False Positive Handling
**Current Limitation:** Aggressive detection may block legitimate users behind corporate NAT.
**Mitigation Strategy:** CAPTCHA-based bypass after repeated false positives, potential behavioral analysis for legitimate patterns.

### Logging Architecture
**Decision:** Synchronous file logging with severity-based separation.
**Rationale:** Ensures security events are captured, structured for SIEM integration.
**Production Considerations:** Requires log rotation/cleaning and async logging for high-volume deployments.

### Scalability Approach
**Horizontal Scaling:** Add proxy instances behind load balancer for increased processing.
---

## System Limitations
- **Detection:** Focuses on common attack patterns, only handles JSON POST data
- **Scalability:** In-memory state, synchronous processing, requires cleanup for production
- **Operational:** Cross-request attack correlation not implemented, socket IP may impact load-balanced users

---

## Testing & Usage

```bash
# Start target server
node src/index.js

# Start proxy server  
node src/proxy.js

# Access test interface
http://localhost:3000/test/
```

**Request Flow:** Browser → Proxy (3000) → Target (3001) → Response back

**Log Output:** Security events in `logs/security-{critical|high|medium}.log`
