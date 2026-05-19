/**
 * Load Balancer - Distributes packets to Fast Paths
 * Converted from C++ to JavaScript
 */

const { FiveTuple } = require('./types');

class LoadBalancer {
    constructor(lbId, fpsPerLb, fpQueues) {
        this.lb_id = lbId;
        this.fps_per_lb = fpsPerLb;
        this.fp_queues = fpQueues;
        
        // Create input queue for this LB
        this.input_queue = { packets: [] };
        
        this.stats = {
            total_received: 0,
            total_dispatched: 0
        };
    }

    getInputQueue() {
        return this.input_queue;
    }

    dispatchPacket(packet) {
        // Hash-based distribution: use five-tuple hash to select FP
        const fpIndex = this.selectFastPath(packet.tuple);
        
        // Add to FP queue
        if (fpIndex >= 0 && fpIndex < this.fp_queues.length) {
            this.fp_queues[fpIndex].packets.push(packet);
            this.stats.total_dispatched++;
        }
    }

    selectFastPath(tuple) {
        const hash = tuple.getHash();
        return Math.abs(hash) % this.fps_per_lb;
    }

    getStats() {
        return { ...this.stats };
    }

    recordReceived() {
        this.stats.total_received++;
    }
}

class LBManager {
    constructor(numLbs, fpsPerLb, fpQueues) {
        this.lbs = [];
        this.num_lbs = numLbs;
        this.fps_per_lb = fpsPerLb;
        
        for (let i = 0; i < numLbs; i++) {
            this.lbs.push(new LoadBalancer(i, fpsPerLb, fpQueues));
        }
    }

    getLBForPacket(tuple) {
        // Hash-based load balancing
        const hash = tuple.getHash();
        const lbIndex = Math.abs(hash) % this.lbs.length;
        return this.lbs[lbIndex];
    }

    async startAll() {
        // In JavaScript, we don't need explicit thread starting
        console.log('[LBManager] All LBs ready');
    }

    stopAll() {
        console.log('[LBManager] All LBs stopped');
    }

    getAggregatedStats() {
        let totalReceived = 0;
        let totalDispatched = 0;
        
        for (const lb of this.lbs) {
            const stats = lb.getStats();
            totalReceived += stats.total_received;
            totalDispatched += stats.total_dispatched;
        }
        
        return {
            total_received: totalReceived,
            total_dispatched: totalDispatched
        };
    }
}

module.exports = { LoadBalancer, LBManager };
