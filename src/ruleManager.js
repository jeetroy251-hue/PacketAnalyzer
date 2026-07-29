/**
 * Rule Manager - Manages blocking/filtering rules
 * Converted from C++ to JavaScript
 */

const { AppType, appTypeToString } = require('./types');

class RuleManager {
    constructor() {
        this.blocked_ips = new Set();
        this.blocked_apps = new Set();
        this.blocked_domains = new Set();
        this.domain_patterns = [];
        this.blocked_ports = new Set();
    }

    // ========== IP Blocking ==========

    blockIP(ip) {
        if (typeof ip === 'string') {
            ip = this.parseIP(ip);
        }
        this.blocked_ips.add(ip);
        console.log(`[RuleManager] Blocked IP: ${this.ipToString(ip)}`);
    }

    unblockIP(ip) {
        if (typeof ip === 'string') {
            ip = this.parseIP(ip);
        }
        this.blocked_ips.delete(ip);
        console.log(`[RuleManager] Unblocked IP: ${this.ipToString(ip)}`);
    }

    isIPBlocked(ip) {
        return this.blocked_ips.has(ip);
    }

    getBlockedIPs() {
        const result = [];
        for (const ip of this.blocked_ips) {
            result.push(this.ipToString(ip));
        }
        return result;
    }

    // ========== Application Blocking ==========

    blockApp(app) {
        this.blocked_apps.add(app);
        console.log(`[RuleManager] Blocked app: ${appTypeToString(app)}`);
    }

    unblockApp(app) {
        this.blocked_apps.delete(app);
        console.log(`[RuleManager] Unblocked app: ${appTypeToString(app)}`);
    }

    isAppBlocked(app) {
        return this.blocked_apps.has(app);
    }

    getBlockedApps() {
        return Array.from(this.blocked_apps);
    }

    // ========== Domain Blocking ==========

    blockDomain(domain) {
        if (domain.includes('*')) {
            this.domain_patterns.push(domain);
        } else {
            this.blocked_domains.add(domain);
        }
        console.log(`[RuleManager] Blocked domain: ${domain}`);
    }

    unblockDomain(domain) {
        if (domain.includes('*')) {
            const idx = this.domain_patterns.indexOf(domain);
            if (idx !== -1) {
                this.domain_patterns.splice(idx, 1);
            }
        } else {
            this.blocked_domains.delete(domain);
        }
        console.log(`[RuleManager] Unblocked domain: ${domain}`);
    }

    isDomainBlocked(domain) {
        if (!domain || domain.length === 0) {
            return false;
        }
        
        // Check exact and suffix match for blocked domains (avoids false positives like fake-msn.com)
        const lowerDomain = domain.toLowerCase();
        for (const blockedDomain of this.blocked_domains) {
            const lowerBlocked = blockedDomain.toLowerCase();
            // Match exact: msn.com == msn.com
            // Or suffix: srtb.msn.com ends with .msn.com
            if (lowerDomain === lowerBlocked || lowerDomain.endsWith('.' + lowerBlocked)) {
                // Debug: Show successful match
                process.stderr.write(`[RuleManager] Domain match: "${domain}" matches blocked domain "${blockedDomain}"\n`);
                return true;
            }
        }
        
        // Check wildcard patterns (e.g., *.example.com)
        for (const pattern of this.domain_patterns) {
            const lowerPattern = pattern.toLowerCase();
            if (this.domainMatchesPattern(lowerDomain, lowerPattern)) {
                // Debug: Show successful pattern match
                process.stderr.write(`[RuleManager] Domain match: "${domain}" matches pattern "${pattern}"\n`);
                return true;
            }
        }
        
        return false;
    }

    getBlockedDomains() {
        const result = Array.from(this.blocked_domains);
        result.push(...this.domain_patterns);
        return result;
    }

    // ========== Port Blocking ==========

    blockPort(port) {
        this.blocked_ports.add(port);
        console.log(`[RuleManager] Blocked port: ${port}`);
    }

    unblockPort(port) {
        this.blocked_ports.delete(port);
    }

    isPortBlocked(port) {
        return this.blocked_ports.has(port);
    }

    // ========== Combined Check ==========

    shouldBlock(srcIp, dstPort, app, domain = '') {
        const reasons = [];

        if (this.isIPBlocked(srcIp)) {
            reasons.push({
                type: 'IP',
                detail: this.ipToString(srcIp)
            });
        }

        if (this.isPortBlocked(dstPort)) {
            reasons.push({
                type: 'PORT',
                detail: String(dstPort)
            });
        }

        if (this.isAppBlocked(app)) {
            reasons.push({
                type: 'APP',
                detail: appTypeToString(app)
            });
        }

        if (domain && domain.length > 0 && this.isDomainBlocked(domain)) {
            reasons.push({
                type: 'DOMAIN',
                detail: domain
            });
        }

        return reasons.length > 0 ? reasons : null;
    }

    // ========== Persistence ==========

    saveRules(filename) {
        const fs = require('fs');
        try {
            let content = '[BLOCKED_IPS]\n';
            for (const ip of this.getBlockedIPs()) {
                content += `${ip}\n`;
            }
            
            content += '\n[BLOCKED_APPS]\n';
            for (const app of this.getBlockedApps()) {
                content += `${appTypeToString(app)}\n`;
            }
            
            content += '\n[BLOCKED_DOMAINS]\n';
            for (const domain of this.getBlockedDomains()) {
                content += `${domain}\n`;
            }
            
            content += '\n[BLOCKED_PORTS]\n';
            for (const port of this.blocked_ports) {
                content += `${port}\n`;
            }
            
            fs.writeFileSync(filename, content);
            console.log(`[RuleManager] Rules saved to ${filename}`);
            return true;
        } catch (error) {
            console.error(`[RuleManager] Error saving rules: ${error.message}`);
            return false;
        }
    }

    loadRules(filename) {
        const fs = require('fs');
        try {
            if (!fs.existsSync(filename)) {
                console.warn(`[RuleManager] Rules file not found: ${filename}`);
                return false;
            }
            
            const content = fs.readFileSync(filename, 'utf8');
            const lines = content.split('\n');
            
            let currentSection = '';
            
            for (const line of lines) {
                const trimmed = line.trim();
                
                if (trimmed.length === 0) continue;
                if (trimmed.startsWith(';')) continue;
                
                if (trimmed.startsWith('[')) {
                    currentSection = trimmed;
                    continue;
                }
                
                if (currentSection === '[BLOCKED_IPS]') {
                    this.blockIP(trimmed);
                } else if (currentSection === '[BLOCKED_APPS]') {
                    for (const [key, value] of Object.entries(AppType)) {
                        if (appTypeToString(value) === trimmed) {
                            this.blockApp(value);
                            break;
                        }
                    }
                } else if (currentSection === '[BLOCKED_DOMAINS]') {
                    this.blockDomain(trimmed);
                } else if (currentSection === '[BLOCKED_PORTS]') {
                    this.blockPort(parseInt(trimmed));
                }
            }
            
            console.log(`[RuleManager] Rules loaded from ${filename}`);
            return true;
        } catch (error) {
            console.error(`[RuleManager] Error loading rules: ${error.message}`);
            return false;
        }
    }

    clearAll() {
        this.blocked_ips.clear();
        this.blocked_apps.clear();
        this.blocked_domains.clear();
        this.domain_patterns = [];
        this.blocked_ports.clear();
    }

    getStats() {
        return {
            blocked_ips: this.blocked_ips.size,
            blocked_apps: this.blocked_apps.size,
            blocked_domains: this.blocked_domains.size + this.domain_patterns.length,
            blocked_ports: this.blocked_ports.size
        };
    }

    // ========== Helper Methods ==========

    parseIP(ipStr) {
        const parts = ipStr.split('.');
        if (parts.length !== 4) return 0;
        
        let result = 0;
        for (let i = 0; i < 4; i++) {
            result |= (parseInt(parts[i]) & 0xFF) << (i * 8);
        }
        return result >>> 0;
    }

    ipToString(ip) {
        return `${(ip >> 0) & 0xFF}.${(ip >> 8) & 0xFF}.${(ip >> 16) & 0xFF}.${(ip >> 24) & 0xFF}`;
    }

    static domainMatchesPattern(domain, pattern) {
        // Handle *.example.com pattern
        if (pattern.length >= 2 && pattern[0] === '*' && pattern[1] === '.') {
            const suffix = pattern.substring(1);  // .example.com
            
            // Check if domain ends with the pattern
            if (domain.length >= suffix.length && domain.endsWith(suffix)) {
                return true;
            }
            
            // Also match the bare domain (example.com matches *.example.com)
            if (domain === pattern.substring(2)) {
                return true;
            }
        }
        
        return false;
    }

    domainMatchesPattern(domain, pattern) {
        return RuleManager.domainMatchesPattern(domain, pattern);
    }
}

module.exports = { RuleManager };
