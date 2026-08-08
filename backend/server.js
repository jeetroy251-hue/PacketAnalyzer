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

app.post('/start-analysis', upload.single('pcap'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'PCAP file is required.' });
        }

        const inputFile = req.file.path;
        const outputFile = path.join(uploadDir, `output-${Date.now()}.pcap`);
        const lbs = parseInt(req.body.lbs, 10) || 2;
        const fpsPerLb = parseInt(req.body.fpsPerLb, 10) || 4;
        const rulesFile = req.body.rulesFile || '';

        const blockApps = normalizeBlockValues(req.body.blockApps);
        const blockIps = normalizeBlockValues(req.body.blockIps);
        const blockDomains = normalizeBlockValues(req.body.blockDomains);

        console.log('[Server] Received block rules', {
            apps: blockApps,
            ips: blockIps,
            domains: blockDomains
        });

        currentSession = {
            status: 'running',
            startedAt: new Date().toISOString(),
            finishedAt: null,
            stats: {},
            report: {},
            error: null,
            outputFile: null
        };

        const engine = new DPIEngine({
            num_load_balancers: lbs,
            fps_per_lb: fpsPerLb,
            rules_file: rulesFile,
            verbose: false,
            eventLimit: 500
        });

        await engine.initialize();

        for (const appName of blockApps) {
            const appType = stringToAppType(appName);
            if (appType === AppType.UNKNOWN && appName.toString().trim().toUpperCase() !== 'UNKNOWN') {
                continue;
            }
            engine.blockApp(appType);
        }

        for (const ip of blockIps) {
            engine.blockIP(ip);
        }

        for (const domain of blockDomains) {
            engine.blockDomain(domain);
        }

        const success = await engine.processFile(inputFile, outputFile);

        if (!success && fs.existsSync(outputFile)) {
            fs.unlinkSync(outputFile);
        }

        currentSession = {
            status: success ? 'completed' : 'failed',
            startedAt: currentSession.startedAt,
            finishedAt: new Date().toISOString(),
            stats: engine.getStats(),
            report: engine.getReportJSON(),
            error: success ? null : engine.lastError || 'Processing failed',
            outputFile: success ? path.basename(outputFile) : null
        };

        return res.status(success ? 200 : 500).json({
            success,
            status: currentSession.status,
            stats: currentSession.stats,
            report: currentSession.report,
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
        return res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/reset', (req, res) => {
    currentSession = {
        status: 'idle',
        startedAt: null,
        finishedAt: null,
        stats: { ...emptyStats },
        report: { connections: { ...emptyConnections }, events: [] },
        error: null,
        outputFile: null
    };
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
            ...(currentSession.report.connections || {})
        },
        rules: currentSession.report.rules || {}
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
    res.json({
        status: currentSession.status,
        events: currentSession.report.events || [],
        packet_details: currentSession.report.packet_details || []
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

    res.status(200).json({
        success: true,
        message: 'DPI backend is running'
    });
});

const port = process.env.PORT || 3000;

app.listen(port, '0.0.0.0', () => {
    console.log(`DPI backend server is running on http://localhost:${port}`);
});