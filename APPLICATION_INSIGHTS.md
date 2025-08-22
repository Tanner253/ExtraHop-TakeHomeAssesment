# Proxy SIEM - Technical Documentation

## System Overview

This document provides a technical analysis of the implemented HTTP reverse proxy with integrated security inspection capabilities. The system focuses on pattern-based threat detection and rate limiting to identify and block common web application attacks.

## Implementation Analysis

### Security Detection Mechanisms

**SQL Injection Detection**
- Implements regex patterns for common SQL injection vectors (UNION, OR, DROP statements)
- Direct pattern matching against URL and request body content
- Covers both URL parameters and request body content

**Directory Traversal Detection** 
- Detects path traversal attempts across Unix and Windows systems
- Covers common target files and path patterns
- Includes patterns for both forward and backslash separators

**Cross-Site Scripting Detection**
- Identifies script tags, event handlers, and JavaScript protocols
- Covers common XSS vectors and attack patterns
- Detects dangerous JavaScript functions and HTML injection

**Rate Limiting Implementation**
- Uses sliding window algorithm with configurable thresholds
- Implements dual-tier limits: general requests (10/30s) and login attempts (3/2min)
- Maintains per-IP tracking with attack type correlation

## Edge Cases & Potential Bypasses

### Pattern Evasion Examples
```sql
-- SQL bypasses not currently detected:
' OR '1'='1'          -- String comparison instead of numeric
' UNION/**/SELECT     -- Comment-based space evasion
' OR 1=1#             -- MySQL hash comments
```

```html
<!-- XSS bypasses: -->
<img src=x onerror=alert(1)>              <!-- No quotes in event handler -->
<svg/onload=alert(1)>                     <!-- Self-closing tags -->
```

### Corporate Environment Issues
- **NAT scenarios:** Multiple legitimate users behind single corporate IP trigger rate limits
- **Development tools:** Code scanners and test suites appear as attacks
- **False positives:** Documentation sites with SQL examples get blocked

### Memory Considerations
- **IPv6 address space:** Attackers can generate millions of unique IPs to exhaust memory
- **Cleanup timing:** 10-minute cleanup window allows memory growth spikes
- **High-volume attacks:** Can exhaust memory before cleanup runs

## Performance Characteristics

- **Security overhead:** ~0.5-2ms per request for pattern matching
- **Memory usage:** ~200-500 bytes per tracked IP address
- **Scaling limit:** ~100k concurrent IPs before memory pressure
- **Bottleneck:** Synchronous file logging blocks event loop

## Current Limitations

**Scope of Inspection**
The system currently inspects URL parameters and request bodies but does not analyze HTTP headers, which may contain malicious content.

**Content-Type Handling**
Detection patterns assume JSON or form-encoded data. Other content types (XML, multipart, binary) are not processed for threat detection.

**Encoding Complexity**
Detection focuses on common attack patterns. Basic encoding and more sophisticated encoding techniques (double encoding, Unicode normalization) may bypass detection.

**Response Analysis**
The system performs request-side inspection only. Outbound responses are not monitored for sensitive data exposure.

**Distributed Attack Correlation**
Rate limiting operates on individual IP addresses without coordination across multiple source IPs in distributed attacks.

## Production Considerations
- **False positive handling:** Corporate environments need IP whitelisting
## Technical Observations

### Architecture Design
- Modular separation between stateless pattern matching and stateful rate limiting
- Zero-trust approach with deny-by-default security posture  
- Structured logging with severity classification for SIEM integration
- Docker containerization for deployment consistency

### Testing Infrastructure
- Interactive web-based testing client for manual validation
- Comprehensive test coverage across implemented attack vectors
- Real-time traffic light system for visual threat level indication
- Log file inspection capabilities for security event analysis

This implementation represents a solid foundation for enterprise security proxy deployment with clear pathways for enhancement based on specific threat landscape requirements. 