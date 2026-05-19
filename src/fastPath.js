/**
 * Fast Path - Processes packets in fast path threads
 * Converted from C++ to JavaScript
 */

const { ConnectionTracker } = require('./connectionTracker');
const { RuleManager } = require('./ruleManager');
const { appTypeToString, sniToAppType, PacketAction } = require('./types');
const { PayloadExtractor } = require('./sniExtractor');

class FastPath {
    constructor(fpId, ruleManager, outputCallback) {
        this.fp_id = fpId;
        this.rule_manager = ruleManager;
        this.output_callback = outputCallback;
        this.connection_tracker = new ConnectionTracker(fpId);
        
        this.stats = {
            total_processed: 0,
            total_forwarded: 0,
            total_dropped: 0
        };
    }

    processPacket(job) {
        this.stats.total_processed++;
        
        // Get or create connection
        const conn = this.connection_tracker.getOrCreateConnection(job.tuple);
        
        // Update connection stats
        const isOutbound = true;  // For simplicity, assume outbound
        this.connection_tracker.updateConnection(conn, job.data.length, isOutbound);
        
        // Try to extract domain/SNI from payload
        let domain = '';
        if (job.payload_data && job.payload_length > 0) {
            domain = PayloadExtractor.extractServerName(job.payload_data, job.tuple.protocol) || '';
            
            // Classify connection if we found domain
            if (domain && domain.length > 0) {
                const appType = sniToAppType(domain);
                this.connection_tracker.classifyConnection(conn, appType, domain);
            }
        }
        
        // Debug: Log domain extraction and active rule list for troubleshooting
        const activeBlockedDomains = this.rule_manager.getBlockedDomains() || [];
        const logDomain = domain || '(no domain extracted)';
        process.stderr.write(`[DPI Debug] Detected domain: "${logDomain}" | Active Rules: ${JSON.stringify(activeBlockedDomains)}\n`);
        if (!domain) {
            process.stderr.write('[DPI Debug] Warning: Packet domain is undefined or empty string.\n');
        }
        
        // Local JS engine verification: check domain rules with suffix matching
        const domainRuleMatched = domain && activeBlockedDomains.some((rule) => {
            if (!rule) return false;
            const lowerDomain = domain.toLowerCase();
            const lowerRule = rule.toLowerCase();
            return lowerDomain === lowerRule || lowerDomain.endsWith('.' + lowerRule);
        });
        if (domainRuleMatched) {
            process.stderr.write(`[DPI ACTION] BLOCKED packet for domain: ${domain} due to rule list: ${JSON.stringify(activeBlockedDomains)}\n`);
        }
        
        // Check blocking rules
        const blockReason = this.rule_manager.shouldBlock(
            job.tuple.src_ip,
            job.tuple.dst_port,
            conn.app_type,
            domain
        );
        
        let action = PacketAction.FORWARD;
        
        if (blockReason) {
            action = PacketAction.DROP;
            this.connection_tracker.blockConnection(conn);
            this.stats.total_dropped++;
            // Debug: Log blocked packets
            process.stderr.write(`[FastPath] Pkt ${job.packet_id} BLOCKED - ${blockReason.type}: ${blockReason.detail} (domain: ${domain})\n`);
        } else {
            this.stats.total_forwarded++;
        }
        
        // Call output callback with block reason
        if (this.output_callback) {
            this.output_callback(job, action, blockReason, domain);
        }
        
        return action;
    }

    getConnectionTracker() {
        return this.connection_tracker;
    }

    getStats() {
        return { ...this.stats };
    }

    getAggregatedStats() {
        const trackerStats = this.connection_tracker.getStats();
        return {
            total_processed: this.stats.total_processed,
            total_forwarded: this.stats.total_forwarded,
            total_dropped: this.stats.total_dropped,
            total_connections: trackerStats.active_connections
        };
    }

    generateClassificationReport() {
        const allConns = this.connection_tracker.getAllConnections();
        const appDistribution = {};
        
        for (const conn of allConns) {
            if (!appDistribution[conn.app_type]) {
                appDistribution[conn.app_type] = 0;
            }
            appDistribution[conn.app_type]++;
        }
        
        let report = `\n[FastPath ${this.fp_id}] Classification Report\n`;
        report += '=====================================\n';
        
        for (const [appType, count] of Object.entries(appDistribution)) {
            report += `  ${appTypeToString(parseInt(appType))}: ${count}\n`;
        }
        
        return report;
    }
}

class FPManager {
    constructor(totalFps, ruleManager, outputCallback) {
        this.fps = [];
        this.rule_manager = ruleManager;
        this.output_callback = outputCallback;
        
        for (let i = 0; i < totalFps; i++) {
            this.fps.push(new FastPath(i, ruleManager, outputCallback));
        }
        
        this.input_queues = [];
        for (let i = 0; i < totalFps; i++) {
            this.input_queues.push({ packets: [] });
        }
    }

    getFP(fpId) {
        return this.fps[fpId];
    }

    getQueuePtrs() {
        return this.input_queues;
    }

    async startAll() {
        // In JavaScript, we don't need explicit thread starting
        console.log('[FPManager] All FPs ready');
    }

    stopAll() {
        // Cleanup
        for (const fp of this.fps) {
            fp.getConnectionTracker().cleanupStale();
        }
        console.log('[FPManager] All FPs stopped');
    }

    getAggregatedStats() {
        let totalProcessed = 0;
        let totalForwarded = 0;
        let totalDropped = 0;
        let totalConnections = 0;
        
        for (const fp of this.fps) {
            const stats = fp.getAggregatedStats();
            totalProcessed += stats.total_processed;
            totalForwarded += stats.total_forwarded;
            totalDropped += stats.total_dropped;
            totalConnections += stats.total_connections;
        }
        
        return {
            total_processed: totalProcessed,
            total_forwarded: totalForwarded,
            total_dropped: totalDropped,
            total_connections: totalConnections
        };
    }

    generateClassificationReport() {
        let report = '\n╔══════════════════════════════════════════════════════════════╗\n';
        report += '║            FAST PATH CLASSIFICATION REPORT                    ║\n';
        report += '╠══════════════════════════════════════════════════════════════╣\n';
        
        for (const fp of this.fps) {
            report += fp.generateClassificationReport();
        }
        
        report += '╚══════════════════════════════════════════════════════════════╝\n';
        return report;
    }
}

module.exports = { FastPath, FPManager };
