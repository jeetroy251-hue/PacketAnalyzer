/**
 * Thread-Safe Queue - For inter-thread communication
 * Converted from C++ to JavaScript using async/await
 */

class ThreadSafeQueue {
    constructor(maxSize = 10000) {
        this.maxSize = maxSize;
        this.queue = [];
        this.shutdown = false;
        this.waiters = [];
    }

    async push(item) {
        while (this.queue.length >= this.maxSize && !this.shutdown) {
            await new Promise(resolve => {
                this.waiters.push(resolve);
            });
        }
        
        if (this.shutdown) return;
        
        this.queue.push(item);
        this.notifyWaiters();
    }

    async pop(timeoutMs = 100) {
        if (this.queue.length === 0 && this.shutdown) {
            return null;
        }
        
        if (this.queue.length > 0) {
            const item = this.queue.shift();
            this.notifyWaiters();
            return item;
        }
        
        // Wait for timeout or item availability
        return new Promise(resolve => {
            const timer = setTimeout(() => {
                const idx = this.waiters.indexOf(resolve);
                if (idx !== -1) this.waiters.splice(idx, 1);
                
                if (this.queue.length > 0) {
                    const item = this.queue.shift();
                    this.notifyWaiters();
                    resolve(item);
                } else {
                    resolve(null);
                }
            }, timeoutMs);
            
            this.waiters.push(() => {
                clearTimeout(timer);
                if (this.queue.length > 0) {
                    const item = this.queue.shift();
                    this.notifyWaiters();
                    resolve(item);
                } else if (this.shutdown) {
                    resolve(null);
                }
            });
        });
    }

    shutdown_queue() {
        this.shutdown = true;
        this.notifyWaiters();
    }

    size() {
        return this.queue.length;
    }

    isEmpty() {
        return this.queue.length === 0;
    }

    clear() {
        this.queue = [];
    }

    notifyWaiters() {
        if (this.waiters.length > 0) {
            const waiter = this.waiters.shift();
            if (waiter) waiter();
        }
    }
}

module.exports = { ThreadSafeQueue };
