const express = require('express');

console.log("🔥 DPI SERVER FILE LOADED");
console.log("🔥 SERVER DIRECTORY:", __dirname);

const cors = require('cors');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { DPIEngine } = require('../src/dpiEngine');
const { stringToAppType, AppType } = require('../src/types');

const app = express();
const uploadDir = path.join(__dirname, 'uploads');

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: uploadDir,
    filename: (req, file, cb) => {
        const safeName = `${Date.now()}-${file.originalname}`;
        cb(null, safeName);
    }
});

const upload = multer({ storage });

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/download', express.static(uploadDir));

const emptyStats = {
    total_packets: 0,
    total_bytes: 0,
    tcp_packets: 0,
    udp_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0
};

const emptyConnections = {
    total_active_connections: 0,
    total_connections_seen: 0,
    top_domains: [],
    app_distribution: {}
};

let currentSession = {
    status: 'idle',
    startedAt: null,
    finishedAt: null,
    stats: { ...emptyStats },
    report: { connections: { ...emptyConnections }, events: [] },
    error: null,
    outputFile: null
};

// SSE clients list
let sseClients = [];

// SSE event broadcast helper
function broadcastSSE(eventName, data) {
    const payload = `event: ${eventName}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sseClients) {
        try { client.write(payload); } catch (_) { /* ignore dead clients */ }
    }
}

function parseList(value) {
    if (!value) return [];
    if (Array.isArray(value)) return value;
    if (typeof value === 'string') {
        try {
            const parsed = JSON.parse(value);
            if (Array.isArray(parsed)) return parsed;
        } catch {
            return [value];
        }
    }
    return [];
}

function normalizeBlockValues(field) {
    const values = parseList(field);
    return values.map(String).filter(v => v.trim().length > 0);
}

// Background analysis runner — called with setImmediate so response is sent first
async function runAnalysis(inputFile, outputFile, lbs, fpsPerLb, rulesFile, blockApps, blockIps, blockDomains) {
    try {
        const engine = new DPIEngine({
            num_load_balancers: lbs,
            fps_per_lb: fpsPerLb,
            rules_file: rulesFile,
            verbose: false,
            eventLimit: 500,
            // Live event callback — broadcast each event via SSE as it happens
            onEvent: (event) => {
                currentSession.liveEvents = currentSession.liveEvents || [];
                currentSession.liveEvents.push(event);
                // Keep only last 500
                if (currentSession.liveEvents.length > 500) currentSession.liveEvents.shift();
                // Push to SSE clients in real time
                broadcastSSE('packet', event);
            },
            // Progress callback — broadcast live stats
            onProgress: (stats) => {
                currentSession.stats = { ...stats };
                broadcastSSE('stats', stats);
            }
        });

        await engine.initialize();

        for (const appName of blockApps) {
            const appType = stringToAppType(appName);
            if (appType === AppType.UNKNOWN && appName.toString().trim().toUpperCase() !== 'UNKNOWN') {
                continue;
            }
            engine.blockApp(appType);
        }
        for (const ip of blockIps) engine.blockIP(ip);
        for (const domain of blockDomains) engine.blockDomain(domain);

        const success = await engine.processFile(inputFile, outputFile);

        if (!success && fs.existsSync(outputFile)) {
            fs.unlinkSync(outputFile);
        }

        currentSession = {
            ...currentSession,
            status: success ? 'completed' : 'failed',
            finishedAt: new Date().toISOString(),
            stats: engine.getStats(),
            report: engine.getReportJSON(),
            error: success ? null : engine.lastError || 'Processing failed',
            outputFile: success ? path.basename(outputFile) : null
        };

        // Broadcast final status via SSE
        broadcastSSE('status', {
            status: currentSession.status,
            stats: currentSession.stats,
            outputFile: currentSession.outputFile,
            error: currentSession.error
        });

    } catch (error) {
        currentSession = {
            ...currentSession,
            status: 'failed',
            finishedAt: new Date().toISOString(),
            error: error.message
        };
        broadcastSSE('status', { status: 'failed', error: error.message });
        console.error('[runAnalysis] Error:', error.message);
    }
}

// ─── ROUTES ──────────────────────────────────────────────────────────────────

app.post('/start-analysis', upload.single('pcap'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'PCAP file is required.' });
        }

        // Prevent double-start
        if (currentSession.status === 'running' || currentSession.status === 'starting') {
            return res.status(409).json({ success: false, error: 'Analysis already in progress.' });
        }

        const inputFile = req.file.path;
        const outputFile = path.join(uploadDir, `output-${Date.now()}.pcap`);
        const lbs = parseInt(req.body.lbs, 10) || 2;
        const fpsPerLb = parseInt(req.body.fpsPerLb, 10) || 4;
        const rulesFile = req.body.rulesFile || '';

        const blockApps = normalizeBlockValues(req.body.blockApps);
        const blockIps = normalizeBlockValues(req.body.blockIps);
        const blockDomains = normalizeBlockValues(req.body.blockDomains);

        console.log('[Server] Received block rules', { apps: blockApps, ips: blockIps, domains: blockDomains });

        // Reset session immediately
        currentSession = {
            status: 'running',
            startedAt: new Date().toISOString(),
            finishedAt: null,
            stats: { ...emptyStats },
            report: { connections: { ...emptyConnections }, events: [] },
            liveEvents: [],
            error: null,
            outputFile: null
        };

        // ── KEY CHANGE: Respond immediately, run analysis in background ──
        res.json({ success: true, status: 'running' });

        // setImmediate ensures response is flushed BEFORE analysis starts
        setImmediate(() => {
            runAnalysis(inputFile, outputFile, lbs, fpsPerLb, rulesFile, blockApps, blockIps, blockDomains);
        });

    } catch (error) {
        currentSession = { ...currentSession, status: 'failed', finishedAt: new Date().toISOString(), error: error.message };
        return res.status(500).json({ success: false, error: error.message });
    }
});

// SSE endpoint — frontend connects here for real-time events
app.get('/events/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Needed for Nginx on Render
    res.flushHeaders();

    // Send current status immediately on connect
    res.write(`event: status\ndata: ${JSON.stringify({ status: currentSession.status, stats: currentSession.stats })}\n\n`);

    sseClients.push(res);

    req.on('close', () => {
        sseClients = sseClients.filter(c => c !== res);
    });
});

app.post('/reset', (req, res) => {
    currentSession = {
        status: 'idle',
        startedAt: null,
        finishedAt: null,
        stats: { ...emptyStats },
        report: { connections: { ...emptyConnections }, events: [] },
        liveEvents: [],
        error: null,
        outputFile: null
    };
    broadcastSSE('status', { status: 'idle' });
    return res.json({ success: true });
});

app.get('/stats', (req, res) => {
    res.json({
        status: currentSession.status,
        stats: currentSession.stats || { ...emptyStats },
        startedAt: currentSession.startedAt,
        finishedAt: currentSession.finishedAt,
        outputFile: currentSession.outputFile
    });
});

app.get('/connections', (req, res) => {
    res.json({
        status: currentSession.status,
        connections: {
            ...emptyConnections,
            ...(currentSession.report?.connections || {})
        },
        rules: currentSession.report?.rules || {}
    });
});

app.get('/report', (req, res) => {
    res.json({
        status: currentSession.status,
        report: currentSession.report || {},
        error: currentSession.error
    });
});

app.get('/events', (req, res) => {
    // Return merged live + report events, deduped by ts
    const reportEvents = currentSession.report?.events || [];
    const liveEvents = currentSession.liveEvents || [];
    const merged = [...liveEvents, ...reportEvents];
    const seen = new Set();
    const unique = merged.filter(e => {
        const k = e.ts + e.message;
        if (seen.has(k)) return false;
        seen.add(k);
        return true;
    });
    res.json({
        status: currentSession.status,
        events: unique,
        packet_details: currentSession.report?.packet_details || []
    });
});

app.get('/status', (req, res) => {
    res.json({
        status: currentSession.status,
        startedAt: currentSession.startedAt,
        finishedAt: currentSession.finishedAt,
        error: currentSession.error
    });
});

app.get('/health', (req, res) => {
    console.log('🔥 HEALTH ROUTE HIT');
    res.status(200).json({ success: true, message: 'DPI backend is running' });
});

const port = process.env.PORT || 3000;
app.listen(port, '0.0.0.0', () => {
    console.log(`DPI backend server is running on http://localhost:${port}`);
});
