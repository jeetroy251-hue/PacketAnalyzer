/**
 * DPI Engine - Main Deep Packet Inspection Engine
 * Converted from C++ to JavaScript
 */

const fs = require('fs');
const { PcapReader } = require('./pcapReader');
const { PacketParser } = require('./packetParser');
const { RuleManager } = require('./ruleManager');
const { FastPath, FPManager } = require('./fastPath');
const { LBManager } = require('./loadBalancer');
const { GlobalConnectionTable } = require('./connectionTracker');
const { PacketJob, FiveTuple, PcapGlobalHeader, PcapPacketHeader, PacketAction, stringToIp, appTypeToString } = require('./types');

class DPIEngine {
    constructor(config = {}) {
        this.config = {
            num_load_balancers: config.num_load_balancers || 2,
            fps_per_lb: config.fps_per_lb || 4,
            rules_file: config.rules_file || '',
            verbose: config.verbose !== false,
            eventLimit: config.eventLimit || 500,
            ...config
        };
        
        this.rule_manager = null;
        this.fp_manager = null;
        this.lb_manager = null;
        this.global_conn_table = null;
        
        this.running = false;
        this.processing_complete = false;
        this.lastError = null;
        
        this.output_file = null;
        this.output_filename = '';
        
        this.stats = {
            total_packets: 0,
            total_bytes: 0,
            tcp_packets: 0,
            udp_packets: 0,
            forwarded_packets: 0,
            dropped_packets: 0
        };
        
        this.events = [];
        
        this.printBanner();
    }

    log(message) {
        const text = String(message);
        if (this.config.verbose) {
            console.log(text);
        }
        this.recordEvent(text);
    }

    recordEvent(message) {
        const entry = {
            ts: new Date().toISOString(),
            message: String(message)
        };
        this.events.push(entry);
        if (this.events.length > this.config.eventLimit) {
            this.events.shift();
        }
    }

    getEventLog() {
        return [...this.events];
    }

    printBanner() {
        if (!this.config.verbose) return;
        console.log('\n╔══════════════════════════════════════════════════════════════╗');
        console.log('║                    DPI ENGINE v1.0                            ║');
        console.log('║               Deep Packet Inspection System                   ║');
        console.log('╠══════════════════════════════════════════════════════════════╣');
        console.log('║ Configuration:                                                ║');
        console.log(`║   Load Balancers:    ${String(this.config.num_load_balancers).padStart(3)} ${' '.repeat(41)}║`);
        console.log(`║   FPs per LB:        ${String(this.config.fps_per_lb).padStart(3)} ${' '.repeat(41)}║`);
        const totalFps = this.config.num_load_balancers * this.config.fps_per_lb;
        console.log(`║   Total FP threads:  ${String(totalFps).padStart(3)} ${' '.repeat(41)}║`);
        console.log('╚══════════════════════════════════════════════════════════════╝\n');
    }

    async initialize() {
        // Create rule manager
        this.rule_manager = new RuleManager();
        
        // Load rules if specified
        if (this.config.rules_file && this.config.rules_file.length > 0) {
            this.rule_manager.loadRules(this.config.rules_file);
        }
        
        // Create output callback
        const outputCb = (job, action) => {
            this.handleOutput(job, action);
        };
        
        // Create FP manager
        const totalFps = this.config.num_load_balancers * this.config.fps_per_lb;
        this.fp_manager = new FPManager(totalFps, this.rule_manager, outputCb);
        
        // Create LB manager
        this.lb_manager = new LBManager(
            this.config.num_load_balancers,
            this.config.fps_per_lb,
            this.fp_manager.getQueuePtrs()
        );
        
        // Create global connection table
        this.global_conn_table = new GlobalConnectionTable(totalFps);
        for (let i = 0; i < totalFps; i++) {
            this.global_conn_table.registerTracker(i, this.fp_manager.getFP(i).getConnectionTracker());
        }
        
        this.log('[DPIEngine] Initialized successfully');
        return true;
    }

    async start() {
        if (this.running) return;
        
        this.running = true;
        this.processing_complete = false;
        
        await this.fp_manager.startAll();
        await this.lb_manager.startAll();
        
        this.log('[DPIEngine] All threads started\n');
    }

    stop() {
        if (!this.running) return;
        
        this.running = false;
        
        if (this.lb_manager) {
            this.lb_manager.stopAll();
        }
        
        if (this.fp_manager) {
            this.fp_manager.stopAll();
        }
        
        this.log('[DPIEngine] All threads stopped\n');
    }

    async processFile(inputFile, outputFile) {
        this.log(`\n[DPIEngine] Processing: ${inputFile}`);
        this.log(`[DPIEngine] Output to:  ${outputFile}\n`);
        
        // Initialize if not already done
        if (!this.rule_manager) {
            if (!(await this.initialize())) {
                return false;
            }
        }
        
        // Open output file
        try {
            this.output_file = fs.createWriteStream(outputFile);
            this.output_filename = outputFile;
        } catch (error) {
            this.lastError = error.message;
            this.log('[DPIEngine] Error: Cannot open output file');
            return false;
        }
        
        // Start processing
        await this.start();
        
        // Process input file
        const readerSuccess = await this.readerThread(inputFile);
        if (!readerSuccess) {
            this.lastError = this.lastError || '[DPIEngine] Error: Reader failed';
        }
        
        // Give time for final packets if processing began successfully
        if (readerSuccess) {
            await this.sleep(200);
        }
        
        // Stop all threads
        this.stop();
        
        // Close output file
        if (this.output_file) {
            this.output_file.end();
        }
        
        if (!readerSuccess) {
            this.log('[DPIEngine] Processing aborted due to reader error');
            return false;
        }
        
        // Print final report
        this.log(this.generateReport());
        this.log(this.fp_manager.generateClassificationReport());
        this.log(this.global_conn_table.generateReport());
        
        return true;
    }

    async readerThread(inputFile) {
        const reader = new PcapReader();
        
        if (!(await new Promise(resolve => {
            setTimeout(() => {
                resolve(reader.open(inputFile));
            }, 0);
        }))) {
            this.lastError = '[Reader] Error: Cannot open input file';
            console.error('[Reader] Error: Cannot open input file');
            return false;
        }
        
        // Write PCAP header to output
        this.writeOutputHeader(reader.getGlobalHeader());
        
        const { RawPacket } = require('./pcapReader');
        const { ParsedPacket } = require('./packetParser');
        
        let packetId = 0;
        let packetCount = 0;
        
        this.log('[Reader] Starting packet processing...\n');
        
        const raw = new RawPacket();
        while (reader.readNextPacket(raw)) {
            // Parse the packet
            const parsed = new ParsedPacket();
            if (!PacketParser.parse(raw, parsed)) {
                continue;
            }
            
            // Only process IP packets with TCP/UDP
            if (!parsed.has_ip || (!parsed.has_tcp && !parsed.has_udp)) {
                continue;
            }
            
            // Create packet job
            const job = this.createPacketJob(raw, parsed, packetId++);
            
            // Update global stats
            this.stats.total_packets++;
            this.stats.total_bytes += raw.data.length;
            
            if (parsed.has_tcp) {
                this.stats.tcp_packets++;
            } else if (parsed.has_udp) {
                this.stats.udp_packets++;
            }
            
            // Send to appropriate LB based on hash
            const lb = this.lb_manager.getLBForPacket(job.tuple);
            lb.recordReceived();
            lb.input_queue.packets.push(job);
            
            // Process packets in queues
            await this.processPendingPackets();
            
            packetCount++;
        }
        
        // Process remaining packets
        await this.processPendingPackets();
        
        this.log(`[Reader] Finished reading ${packetId} packets\n`);
        reader.close();
        
        this.processing_complete = true;
        return true;
    }

    async processPendingPackets() {
        // Process all LB queues
        for (let i = 0; i < this.lb_manager.lbs.length; i++) {
            const lb = this.lb_manager.lbs[i];
            const queue = lb.input_queue;
            
            while (queue.packets.length > 0) {
                const job = queue.packets.shift();
                lb.dispatchPacket(job);
            }
        }
        
        // Process all FP queues
        for (let i = 0; i < this.fp_manager.fps.length; i++) {
            const fp = this.fp_manager.fps[i];
            const queue = this.fp_manager.input_queues[i];
            
            while (queue.packets.length > 0) {
                const job = queue.packets.shift();
                fp.processPacket(job);
            }
        }
    }

    createPacketJob(raw, parsed, packetId) {
        const job = new PacketJob();
        job.packet_id = packetId;
        job.ts_sec = raw.header.ts_sec;
        job.ts_usec = raw.header.ts_usec;
        
        // Set five-tuple
        job.tuple = new FiveTuple(
            stringToIp(parsed.src_ip),
            stringToIp(parsed.dest_ip),
            parsed.src_port,
            parsed.dest_port,
            parsed.protocol
        );
        
        job.tcp_flags = parsed.tcp_flags;
        job.data = raw.data;
        
        // Calculate offsets
        job.eth_offset = 0;
        job.ip_offset = 14;
        
        if (job.data.length > 14) {
            const ipIhl = job.data[14] & 0x0F;
            const ipHeaderLen = ipIhl * 4;
            job.transport_offset = 14 + ipHeaderLen;
            
            if (parsed.has_tcp && job.data.length > job.transport_offset) {
                const tcpDataOffset = (job.data[job.transport_offset + 12] >> 4) & 0x0F;
                const tcpHeaderLen = tcpDataOffset * 4;
                job.payload_offset = job.transport_offset + tcpHeaderLen;
            } else if (parsed.has_udp) {
                job.payload_offset = job.transport_offset + 8;
            }
            
            if (job.payload_offset < job.data.length) {
                job.payload_length = job.data.length - job.payload_offset;
                job.payload_data = job.data.slice(job.payload_offset);
            }
        }
        
        return job;
    }

    handleOutput(job, action, blockReason, domain) {
        if (action === PacketAction.DROP) {
            this.stats.dropped_packets++;
            let logMsg = `Packet ${job.packet_id} blocked`;
            if (blockReason) {
                logMsg += ` (${blockReason.type}`;
                if (blockReason.detail) {
                    logMsg += `: ${blockReason.detail}`;
                }
                logMsg += ')';
            } else if (domain) {
                logMsg += ` (domain: ${domain})`;
            }
            // Log to both console and events
            console.log(logMsg);
            process.stderr.write(`[Output] ${logMsg}\n`);
            this.recordEvent(logMsg);
            return;
        }
        
        this.stats.forwarded_packets++;
        this.recordEvent(`Packet ${job.packet_id} forwarded`);
        this.writeOutputPacket(job);
    }

    writeOutputHeader(header) {
        if (!this.output_file) return;
        
        const buffer = header.toBuffer();
        this.output_file.write(buffer);
    }

    writeOutputPacket(job) {
        if (!this.output_file) return;
        
        const pktHeader = new PcapPacketHeader();
        pktHeader.ts_sec = job.ts_sec;
        pktHeader.ts_usec = job.ts_usec;
        pktHeader.incl_len = job.data.length;
        pktHeader.orig_len = job.data.length;
        
        const headerBuffer = pktHeader.toBuffer();
        this.output_file.write(headerBuffer);
        this.output_file.write(job.data);
    }

    // ========== Rule Management API ==========

    blockIP(ip) {
        if (this.rule_manager) {
            this.rule_manager.blockIP(ip);
        }
    }

    blockApp(app) {
        if (this.rule_manager) {
            this.rule_manager.blockApp(app);
        }
    }

    blockDomain(domain) {
        if (this.rule_manager) {
            this.rule_manager.blockDomain(domain);
        }
    }

    loadRules(filename) {
        if (this.rule_manager) {
            return this.rule_manager.loadRules(filename);
        }
        return false;
    }

    saveRules(filename) {
        if (this.rule_manager) {
            return this.rule_manager.saveRules(filename);
        }
        return false;
    }

    // ========== Reporting ==========

    generateReport() {
        let ss = '\n╔══════════════════════════════════════════════════════════════╗\n';
        ss += '║                    DPI ENGINE STATISTICS                      ║\n';
        ss += '╠══════════════════════════════════════════════════════════════╣\n';
        
        ss += '║ PACKET STATISTICS                                             ║\n';
        ss += `║   Total Packets:      ${String(this.stats.total_packets).padStart(12)} ${' '.repeat(24)}║\n`;
        ss += `║   Total Bytes:        ${String(this.stats.total_bytes).padStart(12)} ${' '.repeat(24)}║\n`;
        ss += `║   TCP Packets:        ${String(this.stats.tcp_packets).padStart(12)} ${' '.repeat(24)}║\n`;
        ss += `║   UDP Packets:        ${String(this.stats.udp_packets).padStart(12)} ${' '.repeat(24)}║\n`;
        
        ss += '╠══════════════════════════════════════════════════════════════╣\n';
        ss += '║ FILTERING STATISTICS                                          ║\n';
        ss += `║   Forwarded:          ${String(this.stats.forwarded_packets).padStart(12)} ${' '.repeat(24)}║\n`;
        ss += `║   Dropped/Blocked:    ${String(this.stats.dropped_packets).padStart(12)} ${' '.repeat(24)}║\n`;
        
        if (this.stats.total_packets > 0) {
            const dropRate = (100.0 * this.stats.dropped_packets / this.stats.total_packets).toFixed(2);
            ss += `║   Drop Rate:          ${String(dropRate + '%').padStart(11)} ${' '.repeat(24)}║\n`;
        }
        
        if (this.lb_manager) {
            const lbStats = this.lb_manager.getAggregatedStats();
            ss += '╠══════════════════════════════════════════════════════════════╣\n';
            ss += '║ LOAD BALANCER STATISTICS                                      ║\n';
            ss += `║   LB Received:        ${String(lbStats.total_received).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   LB Dispatched:      ${String(lbStats.total_dispatched).padStart(12)} ${' '.repeat(24)}║\n`;
        }
        
        if (this.fp_manager) {
            const fpStats = this.fp_manager.getAggregatedStats();
            ss += '╠══════════════════════════════════════════════════════════════╣\n';
            ss += '║ FAST PATH STATISTICS                                          ║\n';
            ss += `║   FP Processed:       ${String(fpStats.total_processed).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   FP Forwarded:       ${String(fpStats.total_forwarded).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   FP Dropped:         ${String(fpStats.total_dropped).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   Active Connections: ${String(fpStats.total_connections).padStart(12)} ${' '.repeat(24)}║\n`;
        }
        
        if (this.rule_manager) {
            const ruleStats = this.rule_manager.getStats();
            ss += '╠══════════════════════════════════════════════════════════════╣\n';
            ss += '║ BLOCKING RULES                                                ║\n';
            ss += `║   Blocked IPs:        ${String(ruleStats.blocked_ips).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   Blocked Apps:       ${String(ruleStats.blocked_apps).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   Blocked Domains:    ${String(ruleStats.blocked_domains).padStart(12)} ${' '.repeat(24)}║\n`;
            ss += `║   Blocked Ports:      ${String(ruleStats.blocked_ports).padStart(12)} ${' '.repeat(24)}║\n`;
        }
        
        ss += '╚══════════════════════════════════════════════════════════════╝\n';
        
        return ss;
    }

    getStats() {
        return { ...this.stats };
    }

    getRuleSummary() {
        if (!this.rule_manager) return null;
        return {
            blocked_ips: this.rule_manager.getBlockedIPs(),
            blocked_apps: this.rule_manager.getBlockedApps().map(app => appTypeToString(app)),
            blocked_domains: this.rule_manager.getBlockedDomains(),
            blocked_ports: Array.from(this.rule_manager.blocked_ports)
        };
    }

    getConnectionSummary() {
        if (!this.global_conn_table) return null;
        return this.global_conn_table.getGlobalStats();
    }

    getReportJSON() {
        return {
            stats: this.getStats(),
            rules: this.getRuleSummary(),
            connections: this.getConnectionSummary(),
            events: this.getEventLog(),
            output_file: this.output_filename
        };
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

module.exports = { DPIEngine };
