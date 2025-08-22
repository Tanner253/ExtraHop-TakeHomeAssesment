'use strict';
require('dotenv').config({ path: '.env' });

const securityTrackingMap = new Map();
const securityLogger = require('./logger');
const logger = new securityLogger();
const levels = logger.enumLevels();

// Environment-based configuration
const generalTimeWindow = parseInt(process.env.GENERAL_TIME_WINDOW) || 30000;
const loginTimeWindow = parseInt(process.env.LOGIN_TIME_WINDOW) || 120000;
const generalMaxRequests = parseInt(process.env.GENERAL_MAX_REQUESTS) || 10;
const loginMaxAttempts = parseInt(process.env.LOGIN_MAX_ATTEMPTS) || 3;
const cleanupInterval = parseInt(process.env.CLEANUP_INTERVAL) || 600000;

const SECURITY_LIMITS = {
    GENERAL: { max: generalMaxRequests, window: generalTimeWindow, level: levels.MEDIUM },
    LOGIN: { max: loginMaxAttempts, window: loginTimeWindow, level: levels.HIGH },
};

// Cleanup old tracking data every 10 minutes
setInterval(() => {
    const cutoffTime = Date.now() - (10 * 60 * 1000); // 10 minutes ago
    for (const [key, value] of securityTrackingMap.entries()) {
        if (key.includes('_history') && value.requests) {
            // Clean old timestamps from rate limit history
            value.requests = value.requests.filter(timestamp => timestamp > cutoffTime);
            if (value.requests.length === 0) {
                securityTrackingMap.delete(key);
            }
        } else if (key.includes('_violation') || key.includes('_attack')) {
            // Remove violation markers older than 10 minutes
            if (!value.timestamp) value.timestamp = Date.now(); // Add timestamp if missing
            if (value.timestamp < cutoffTime) {
                securityTrackingMap.delete(key);
            }
        }
    }
}, cleanupInterval);

//ai generated:
const SQL_INJECTION_PATTERNS = [
    // SQL injection with quotes (most common)
    /'(\s)*(OR|AND)(\s)*(\d+(\s)*=(\s)*\d+|')/i,  // ' OR 1=1 or ' OR '
    /'(\s)*;(\s)*(DROP|DELETE|INSERT|UPDATE)/i,   // '; DROP TABLE
    /'(\s)*--/i,                                  // ' -- (SQL comments)
    /'(\s)*\/\*/i,                                // ' /* (SQL block comments)
    
    // UNION attacks
    /(\bUNION\b)(\s)+(ALL(\s)+)?(\bSELECT\b)/i,   // UNION SELECT
    
    // SQL keywords in suspicious context (with quotes or semicolons)
    /(;|')(\s)*(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)(\s)/i,
];
//ai generated:
const DIRECTORY_TRAVERSAL_PATTERNS = [
    // Basic path traversal
    /\.\.\//gi,                           // ../
    /\.\.\\/gi,                           // ..\ 
    /\.\.%2F/gi,                          // ..%2F
    /\.\.%5C/gi,                          // ..%5C
    /%2E%2E%2F/gi,                        // %2E%2E%2F
    
    // Common targets
    /etc\/passwd/gi,                      // etc/passwd
    /etc\/shadow/gi,                      // etc/shadow
    /windows\/system32/gi,                // windows/system32
    /boot\.ini/gi,                        // boot.ini
];
//ai generated:
const XSS_PATTERNS = [
    // Script tags
    /<script[^>]*>/gi,                   // <script> opening tags
    /<\/script>/gi,                      // </script> closing tags
    
    // JavaScript in attributes
    /javascript:\s*[^;]/gi,              // javascript: protocol with content
    /on\w+\s*=\s*["'][^"']*["']/gi,     // onclick="..." with quotes
    
    // Dangerous functions with parentheses
    /eval\s*\(/gi,                       // eval(
    /alert\s*\(/gi,                      // alert(
    /document\.write\s*\(/gi,            // document.write(
    /document\.cookie\s*=/gi,            // document.cookie=
    
    // HTML injection with attributes
    /<iframe[^>]*src/gi,                 // <iframe src=
    /<img[^>]*onerror/gi,                // <img onerror=
    /<svg[^>]*onload/gi,                 // <svg onload=
    
    // Encoded script attempts
    /%3Cscript/gi,                       // <script encoded
    /&#60;script/gi,                     // <script HTML entity encoded
];

const RequestValidated = (req) => {
    // Prevent circular reference crashes in security checks (only for POST requests with body)
    if (req.body) {
        try {
            JSON.stringify(req.body);
        } catch (err) {
            return { valid: false, reason: 'malformed' };
        }
    }
    
    const statelessPassed = passesStatelessChecks(req);
    const statefulPassed = passesStatefulChecks(req);
    
    if (!statelessPassed) {
        return { valid: false, reason: 'security_threat' };
    }
    if (!statefulPassed) {
        return { valid: false, reason: 'rate_limited' };
    }
    
    return { valid: true };
}

const passesStatelessChecks = (req) => {
    const sqlInjectionDetected = checkForSqlInjection(req);
    const directoryTraversalDetected = checkForDirectoryTraversal(req);
    const scriptInjectionDetected = checkForScriptInjection(req);

    // Debug logging
    console.log(`REQUEST: ${req.url} - SQL:${sqlInjectionDetected} DIR:${directoryTraversalDetected} XSS:${scriptInjectionDetected}`);

    // Return true only if NO threats detected
    return !sqlInjectionDetected && !directoryTraversalDetected && !scriptInjectionDetected;
}

const passesStatefulChecks = (req) => {
    const clientIpAddress = req.socket.remoteAddress;
    const isLoginAttempt = req.path.includes('/login');
    
    // Skip rate limiting for static assets and browser/extension requests
    if (req.path.match(/\.(css|js|html|png|jpg|ico|favicon)$/) || 
        req.path.includes('current-url') || 
        req.path.includes('.identity') ||
        req.path.includes('favicon')) {
        return true;
    }
    
    if (isLoginAttempt) {
        // Login requests check login-specific brute force limits
        return updateRateLimit(clientIpAddress, 'login', SECURITY_LIMITS.LOGIN);
    } else {
        // Non-login requests check general rate limits  
        return updateRateLimit(clientIpAddress, 'general', SECURITY_LIMITS.GENERAL);
    }
}

//time window strategy to prevent brute force attack taking advantage of a set interval or reset mechanism
const updateRateLimit = (clientIpAddress, rateLimitType, securityLimits) => {
    const currentTimestamp = Date.now();
    const rateLimitKey = `${clientIpAddress}_${rateLimitType}_history`;
    
    let ipRequestHistory = securityTrackingMap.get(rateLimitKey) || { requests: [] };
    ipRequestHistory.requests = ipRequestHistory.requests.filter(requestTimestamp => 
        currentTimestamp - requestTimestamp < securityLimits.window
    );
    ipRequestHistory.requests.push(currentTimestamp);
    securityTrackingMap.set(rateLimitKey, ipRequestHistory);

    const rateLimitExceeded = ipRequestHistory.requests.length > securityLimits.max;
    if (rateLimitExceeded) {
        const escalationKey = `${clientIpAddress}_${rateLimitType}_violation`;
        if (!securityTrackingMap.has(escalationKey)) {
            securityTrackingMap.set(escalationKey, { detected: true, timestamp: Date.now() });
        
            const violationDetails = `Rate limit exceeded: ${ipRequestHistory.requests.length}/${securityLimits.max}`;
            logger.log(clientIpAddress, rateLimitType, violationDetails, securityLimits.level);
            checkEscalation(clientIpAddress);
        }
    }
    return !rateLimitExceeded;
}


const checkForSqlInjection = (req) => {
    const checkString = `${decodeURIComponent(req.url)} ${JSON.stringify(req.body || {})}`;
    const sqlFound = SQL_INJECTION_PATTERNS.some(pattern => pattern.test(checkString));
    
    if (sqlFound) {
        logger.log(req.socket.remoteAddress, 'SQL_INJECTION', `SQL injection detected: ${req.url}`, levels.HIGH);
        securityTrackingMap.set(`${req.socket.remoteAddress}_sql_attack`, { detected: true, timestamp: Date.now() });
        checkEscalation(req.socket.remoteAddress);
    }
    
    return sqlFound;
}

const checkForDirectoryTraversal = (req) => {
    const checkString = `${decodeURIComponent(req.url)} ${JSON.stringify(req.body || {})}`;
    const directoryTraversalFound = DIRECTORY_TRAVERSAL_PATTERNS.some(pattern => pattern.test(checkString));
    
    if (directoryTraversalFound) {
        logger.log(req.socket.remoteAddress, 'DIRECTORY_TRAVERSAL', `Directory traversal detected: ${req.url}`, levels.HIGH);
        securityTrackingMap.set(`${req.socket.remoteAddress}_directory_attack`, { detected: true, timestamp: Date.now() });
        checkEscalation(req.socket.remoteAddress);
    }
    return directoryTraversalFound;
}

const checkForScriptInjection = (req) => {
    const checkString = `${decodeURIComponent(req.url)} ${JSON.stringify(req.body || {})}`;
    const scriptInjectionFound = XSS_PATTERNS.some(pattern => pattern.test(checkString));
    
    if (scriptInjectionFound) {
        logger.log(req.socket.remoteAddress, 'SCRIPT_INJECTION', `Script injection detected: ${req.url}`, levels.HIGH);
        securityTrackingMap.set(`${req.socket.remoteAddress}_xss_attack`, { detected: true, timestamp: Date.now() });
        checkEscalation(req.socket.remoteAddress);
    }
    return scriptInjectionFound;
}

const checkEscalation = (clientIpAddress) => {
    const hasGeneralViolations = securityTrackingMap.has(`${clientIpAddress}_general_violation`);
    const hasLoginViolations = securityTrackingMap.has(`${clientIpAddress}_login_violation`);
    const hasSqlAttacks = securityTrackingMap.has(`${clientIpAddress}_sql_attack`);
    const hasDirectoryAttacks = securityTrackingMap.has(`${clientIpAddress}_directory_attack`);
    const hasXssAttacks = securityTrackingMap.has(`${clientIpAddress}_xss_attack`);

    const attackTypes = [];
    if (hasGeneralViolations) attackTypes.push('general_rate_limit');
    if (hasLoginViolations) attackTypes.push('login_rate_limit');
    if (hasSqlAttacks) attackTypes.push('sql_injection');
    if (hasDirectoryAttacks) attackTypes.push('directory_traversal');
    if (hasXssAttacks) attackTypes.push('xss_attack');

    if (attackTypes.length >= 2) {
        const escalationSources = attackTypes.join(' + ');
        logger.log(clientIpAddress, 'ESCALATED_THREAT', `ESCALATED THREAT - Multiple attack types: ${escalationSources}`, levels.CRITICAL);
    }
}

module.exports = {
    RequestValidated
}
