/**
 * Connection Tracker - Track and manage network connections/flows
 * Converted from C++ to JavaScript
 */

const { Connection, ConnectionState, PacketAction, appTypeToString } = require('./types');

class ConnectionTracker {
    constructor(fpId, maxConnections = 100000) {
        this.fp_id = fpId;
        this.max_connections = maxConnections;
        this.connections = new Map();  // Using key-based map for five-tuples
        this.total_seen = 0;
        this.classified_count = 0;
        this.blocked_count = 0;
    }

    getOrCreateConnection(tuple) {
        const key = tuple.getKey();
        
        if (this.connections.has(key)) {
            return this.connections.get(key);
        }
        
        // Check if we need to evict old connections
        if (this.connections.size >= this.max_connections) {
            this.evictOldest();
        }
        
        // Create new connection
        const conn = new Connection();
        conn.tuple = tuple;
        conn.state = ConnectionState.NEW;
        conn.first_seen = Date.now();
        conn.last_seen = Date.now();
        
        this.connections.set(key, conn);
        this.total_seen++;
        
        return conn;
    }

    getConnection(tuple) {
        const key = tuple.getKey();
        if (this.connections.has(key)) {
            return this.connections.get(key);
        }
        
        // Try reverse tuple (for bidirectional matching)
        const revKey = tuple.reverse().getKey();
        if (this.connections.has(revKey)) {
            return this.connections.get(revKey);
        }
        
        return null;
    }

    updateConnection(conn, packetSize, isOutbound) {
        if (!conn) return;
        
        conn.last_seen = Date.now();
        
        if (isOutbound) {
            conn.packets_out++;
            conn.bytes_out += packetSize;
        } else {
            conn.packets_in++;
            conn.bytes_in += packetSize;
        }
    }

    classifyConnection(conn, appType, sni = '') {
        if (!conn) return;
        
        if (conn.state !== ConnectionState.CLASSIFIED) {
            conn.app_type = appType;
            conn.sni = sni;
            conn.state = ConnectionState.CLASSIFIED;
            this.classified_count++;
        }
    }

    blockConnection(conn) {
        if (!conn) return;
        
        conn.state = ConnectionState.BLOCKED;
        conn.action = PacketAction.DROP;
        this.blocked_count++;
    }

    closeConnection(tuple) {
        const key = tuple.getKey();
        if (this.connections.has(key)) {
            const conn = this.connections.get(key);
            conn.state = ConnectionState.CLOSED;
        }
    }

    cleanupStale(timeoutMs = 300000) {
        const now = Date.now();
        let removed = 0;
        
        for (const [key, conn] of this.connections.entries()) {
            const age = now - conn.last_seen;
            
            if (age > timeoutMs || conn.state === ConnectionState.CLOSED) {
                this.connections.delete(key);
                removed++;
            }
        }
        
        return removed;
    }

    getAllConnections() {
        return Array.from(this.connections.values());
    }

    getActiveCount() {
        return this.connections.size;
    }

    getStats() {
        return {
            active_connections: this.connections.size,
            total_connections_seen: this.total_seen,
            classified_connections: this.classified_count,
            blocked_connections: this.blocked_count
        };
    }

    clear() {
        this.connections.clear();
    }

    forEach(callback) {
        for (const [key, conn] of this.connections.entries()) {
            callback(conn);
        }
    }

    evictOldest() {
        if (this.connections.size === 0) return;
        
        let oldest = null;
        let oldestTime = Date.now();
        
        for (const [key, conn] of this.connections.entries()) {
            if (conn.last_seen < oldestTime) {
                oldest = key;
                oldestTime = conn.last_seen;
            }
        }
        
        if (oldest) {
            this.connections.delete(oldest);
        }
    }
}

class GlobalConnectionTable {
    constructor(numFps) {
        this.trackers = new Array(numFps).fill(null);
        this.trackerLock = { locked: false };
    }

    registerTracker(fpId, tracker) {
        if (fpId < this.trackers.length) {
            this.trackers[fpId] = tracker;
        }
    }

    getGlobalStats() {
        const stats = {
            total_active_connections: 0,
            total_connections_seen: 0,
            app_distribution: {},
            top_domains: []
        };
        
        const domainCounts = {};
        
        for (const tracker of this.trackers) {
            if (!tracker) continue;
            
            const trackerStats = tracker.getStats();
            stats.total_active_connections += trackerStats.active_connections;
            stats.total_connections_seen += trackerStats.total_connections_seen;
            
            // Collect app distribution
            tracker.forEach((conn) => {
                if (!stats.app_distribution[conn.app_type]) {
                    stats.app_distribution[conn.app_type] = 0;
                }
                stats.app_distribution[conn.app_type]++;
                
                if (conn.sni && conn.sni.length > 0) {
                    if (!domainCounts[conn.sni]) {
                        domainCounts[conn.sni] = 0;
                    }
                    domainCounts[conn.sni]++;
                }
            });
        }
        
        // Get top domains
        const domainArray = Object.entries(domainCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 20);
        
        stats.top_domains = domainArray.map(([domain, count]) => ({ domain, count }));
        
        return stats;
    }

    generateReport() {
        const stats = this.getGlobalStats();
        
        let report = '\n╔══════════════════════════════════════════════════════════════╗\n';
        report += '║               CONNECTION STATISTICS REPORT                    ║\n';
        report += '╠══════════════════════════════════════════════════════════════╣\n';
        
        report += `║ Active Connections:     ${String(stats.total_active_connections).padStart(10)} ${' '.repeat(26)}║\n`;
        report += `║ Total Connections Seen: ${String(stats.total_connections_seen).padStart(10)} ${' '.repeat(26)}║\n`;
        
        report += '╠══════════════════════════════════════════════════════════════╣\n';
        report += '║                    APPLICATION BREAKDOWN                      ║\n';
        report += '╠══════════════════════════════════════════════════════════════╣\n';
        
        // Calculate total for percentages
        let total = 0;
        for (const count of Object.values(stats.app_distribution)) {
            total += count;
        }
        
        // Sort by count
        const sortedApps = Object.entries(stats.app_distribution)
            .map(([appType, count]) => ({ appType: parseInt(appType), count }))
            .sort((a, b) => b.count - a.count);
        
        for (const { appType, count } of sortedApps) {
            const pct = total > 0 ? (100.0 * count / total) : 0;
            const appName = appTypeToString(appType);
            report += `║ ${appName.padEnd(20)} ${String(count).padStart(10)} (${pct.toFixed(1).padStart(5)}%) ${' '.repeat(10)}║\n`;
        }
        
        if (stats.top_domains.length > 0) {
            report += '╠══════════════════════════════════════════════════════════════╣\n';
            report += '║                      TOP DOMAINS                             ║\n';
            report += '╠══════════════════════════════════════════════════════════════╣\n';
            
            for (const { domain, count } of stats.top_domains) {
                let displayDomain = domain;
                if (displayDomain.length > 35) {
                    displayDomain = displayDomain.substring(0, 32) + '...';
                }
                report += `║ ${displayDomain.padEnd(40)} ${String(count).padStart(10)} ${' '.repeat(11)}║\n`;
            }
        }
        
        report += '╚══════════════════════════════════════════════════════════════╝\n';
        
        return report;
    }
}

module.exports = {
    ConnectionTracker,
    GlobalConnectionTable
};
