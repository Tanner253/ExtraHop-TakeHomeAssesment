'use strict';

const path = require('path');
const fs = require('fs');

class SecurityLogger {
    constructor(){
        this.logsDir = path.join(__dirname, '../logs');

        if(!fs.existsSync(this.logsDir)){
            fs.mkdirSync(this.logsDir);
        }
    }

    log(ip, type, details, level){
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const logEntry = `[${timestamp}] ${level.toUpperCase()} | IP: ${ip} | ${type} | ${details}\n`;
        const logFile = path.join(this.logsDir, `security-${level}.log`);
        fs.appendFileSync(logFile, logEntry);
    }

    enumLevels(){
        return {
            CRITICAL: 'critical',
            HIGH: 'high',
            MEDIUM: 'medium',
            LOW: 'low'
        }
    }
}

module.exports = SecurityLogger;

