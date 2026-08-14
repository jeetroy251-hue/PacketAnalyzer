import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_BASE_URL;

// Colors for pie chart slices
const PIE_COLORS = ['#38bdf8', '#818cf8', '#34d399', '#f472b6', '#fb923c', '#a78bfa', '#facc15', '#f87171'];

function StatsCard({ label, value, color }) {
  return (
    <div className="rounded-3xl bg-panel p-4 shadow-xl shadow-slate-900/30">
      <p className="text-slate-400 text-sm">{label}</p>
      <p className={`mt-3 text-3xl font-semibold ${color}`}>{value ?? 0}</p>
    </div>
  );
}

// Animated progress bar shown while analysis is running
function ProgressBar({ total, forwarded, dropped }) {
  const pct = total > 0 ? Math.min(100, Math.round(((forwarded + dropped) / total) * 100)) : 0;
  return (
    <div className="rounded-3xl border border-slate-700 bg-slate-900 p-4">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="text-slate-300">Analysis running...</span>
        <span className="text-slate-400">{forwarded + dropped} / {total} packets</span>
      </div>
      <div className="h-3 overflow-hidden rounded-full bg-slate-800">
        <div
          className="h-full rounded-full bg-sky-500 transition-all duration-300"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-2 flex gap-4 text-xs text-slate-400">
        <span className="text-green-400">▲ Forwarded: {forwarded}</span>
        <span className="text-rose-400">▼ Dropped: {dropped}</span>
      </div>
    </div>
  );
}

export default function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus]             = useState('idle');
  const [isAnalyzing, setIsAnalyzing]   = useState(false);
  const fileInputRef = useRef(null);
  const sseRef       = useRef(null);   // SSE EventSource reference

  const [stats, setStats] = useState({
    total_packets: 0,
    tcp_packets: 0,
    udp_packets: 0,
    forwarded_packets: 0,
    dropped_packets: 0
  });
  const [connections, setConnections] = useState({
    total_active_connections: 0,
    total_connections_seen: 0,
    top_domains: [],
    app_distribution: {}
  });
  const [events, setEvents]       = useState([]);
  const [outputFile, setOutputFile] = useState(null);

  const [blockAppInput,    setBlockAppInput]    = useState('');
  const [blockIpInput,     setBlockIpInput]     = useState('');
  const [blockDomainInput, setBlockDomainInput] = useState('');
  const [blockRules, setBlockRules] = useState({ apps: [], ips: [], domains: [] });

  // ── Derived chart data ─────────────────────────────────────────────────────
  const appDistributionData = useMemo(() =>
    Object.entries(connections.app_distribution || {}).map(([name, value]) => ({ name, value })),
    [connections.app_distribution]
  );

  const packetDistributionData = useMemo(() => [
    { name: 'Forwarded', value: stats.forwarded_packets || 0 },
    { name: 'Dropped',   value: stats.dropped_packets   || 0 }
  ], [stats.forwarded_packets, stats.dropped_packets]);

  // ── SSE setup ──────────────────────────────────────────────────────────────
  function connectSSE() {
    // Close any existing connection first
    if (sseRef.current) {
      sseRef.current.close();
      sseRef.current = null;
    }

    const es = new EventSource(`${API_BASE}/events/stream`);
    sseRef.current = es;

    // Live packet events → prepend to log (max 50 shown)
    es.addEventListener('packet', (e) => {
      try {
        const event = JSON.parse(e.data);
        setEvents(prev => [event, ...prev].slice(0, 50));
      } catch (_) {}
    });

    // Live stats update during processing
    es.addEventListener('stats', (e) => {
      try {
        const s = JSON.parse(e.data);
        setStats(s);
      } catch (_) {}
    });

    // Final status (completed / failed)
    es.addEventListener('status', (e) => {
      try {
        const payload = JSON.parse(e.data);
        setStatus(payload.status || 'idle');

        if (payload.status === 'completed' || payload.status === 'failed') {
          setIsAnalyzing(false);
          if (payload.stats)      setStats(payload.stats);
          if (payload.outputFile) setOutputFile(payload.outputFile);
          // Fetch final connections once analysis is done
          fetchConnections();
        }
      } catch (_) {}
    });

    es.onerror = () => {
      // SSE connection dropped — reconnect after 2s if still analyzing
      if (isAnalyzing) {
        setTimeout(connectSSE, 2000);
      }
    };
  }

  // ── On mount: reset backend + open SSE + start polling ────────────────────
  useEffect(() => {
    fetch(`${API_BASE}/reset`, { method: 'POST' }).catch(() => {});
    connectSSE();

    // Polling for stats + connections (every 2s) — lighter than before
    const interval = setInterval(() => {
      fetchStats();
      fetchConnections();
    }, 2000);

    return () => {
      clearInterval(interval);
      if (sseRef.current) {
        sseRef.current.close();
        sseRef.current = null;
      }
    };
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Data fetchers (used by polling + after reset) ──────────────────────────
  async function fetchStats() {
    try {
      const res  = await fetch(`${API_BASE}/stats`);
      const json = await res.json();
      if (json.stats)      setStats(json.stats);
      if (json.outputFile) setOutputFile(json.outputFile);
      if (json.status) {
        setStatus(json.status);
        if (json.status === 'completed' || json.status === 'failed') {
          setIsAnalyzing(false);
        }
      }
    } catch (_) {}
  }

  async function fetchConnections() {
    try {
      const res  = await fetch(`${API_BASE}/connections`);
      const json = await res.json();
      if (json.connections) {
        setConnections({
          total_active_connections: 0,
          total_connections_seen: 0,
          top_domains: [],
          app_distribution: {},
          ...json.connections
        });
      }
    } catch (_) {}
  }

  // ── File input ─────────────────────────────────────────────────────────────
  const handleFileChange = (e) => setSelectedFile(e.target.files?.[0] || null);

  const handleResetFile = async () => {
    setSelectedFile(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
    try { await fetch(`${API_BASE}/reset`, { method: 'POST' }); } catch (_) {}
    setIsAnalyzing(false);
    setStatus('idle');
    setStats({ total_packets: 0, tcp_packets: 0, udp_packets: 0, forwarded_packets: 0, dropped_packets: 0 });
    setConnections({ total_active_connections: 0, total_connections_seen: 0, top_domains: [], app_distribution: {} });
    setEvents([]);
    setOutputFile(null);
    setBlockRules({ apps: [], ips: [], domains: [] });
  };

  // ── Blocking rules ─────────────────────────────────────────────────────────
  const addRule = (type) => {
    if (type === 'app' && blockAppInput.trim()) {
      setBlockRules(p => ({ ...p, apps: [...p.apps, blockAppInput.trim()] }));
      setBlockAppInput('');
    }
    if (type === 'ip' && blockIpInput.trim()) {
      setBlockRules(p => ({ ...p, ips: [...p.ips, blockIpInput.trim()] }));
      setBlockIpInput('');
    }
    if (type === 'domain' && blockDomainInput.trim()) {
      setBlockRules(p => ({ ...p, domains: [...p.domains, blockDomainInput.trim()] }));
      setBlockDomainInput('');
    }
  };

  const removeRule = (type, value) => {
    setBlockRules(p => ({
      apps:    type === 'app'    ? p.apps.filter(i => i !== value)    : p.apps,
      ips:     type === 'ip'     ? p.ips.filter(i => i !== value)     : p.ips,
      domains: type === 'domain' ? p.domains.filter(i => i !== value) : p.domains
    }));
  };

  // ── Start analysis ─────────────────────────────────────────────────────────
  const handleStart = async () => {
    if (!selectedFile) { alert('Please upload a PCAP file first.'); return; }
    if (isAnalyzing)   { alert('Analysis already in progress.'); return; }

    const formData = new FormData();
    formData.append('pcap',         selectedFile);
    formData.append('lbs',          '2');
    formData.append('fpsPerLb',     '4');
    formData.append('blockApps',    JSON.stringify(blockRules.apps));
    formData.append('blockIps',     JSON.stringify(blockRules.ips));
    formData.append('blockDomains', JSON.stringify(blockRules.domains));

    // Clear previous results immediately
    setStatus('running');
    setIsAnalyzing(true);
    setEvents([]);
    setStats({ total_packets: 0, tcp_packets: 0, udp_packets: 0, forwarded_packets: 0, dropped_packets: 0 });
    setConnections({ total_active_connections: 0, total_connections_seen: 0, top_domains: [], app_distribution: {} });
    setOutputFile(null);

    // Reconnect SSE so we start receiving fresh events
    connectSSE();

    try {
      const response = await fetch(`${API_BASE}/start-analysis`, { method: 'POST', body: formData });
      const result   = await response.json();

      if (!result.success) {
        // Backend rejected immediately (e.g. no file, already running)
        setStatus('failed');
        setIsAnalyzing(false);
        alert(result.error || 'Analysis failed to start.');
      }
      // If success: status is now 'running' — SSE will deliver all updates
    } catch (error) {
      setStatus('failed');
      setIsAnalyzing(false);
      alert(error.message);
    }
  };

  // ── Status badge color ─────────────────────────────────────────────────────
  const statusColor = {
    idle:      'bg-slate-700 text-slate-300',
    running:   'bg-sky-900 text-sky-300',
    completed: 'bg-green-900 text-green-300',
    failed:    'bg-rose-900 text-rose-300'
  }[status] || 'bg-slate-700 text-slate-300';

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 px-4 py-6 md:px-10">

      {/* Header */}
      <header className="mb-8 rounded-3xl border border-slate-700 bg-panel/80 p-6 shadow-xl shadow-slate-900/40 backdrop-blur-sm">
        <h1 className="text-4xl font-semibold text-white">DPI Dashboard</h1>
        <p className="mt-2 max-w-2xl text-slate-400">
          Upload a PCAP file, then start the analysis to inspect traffic, block apps/domains/IPs, and view live statistics.
        </p>
      </header>

      {/* Controls + Live Logs */}
      <section className="mb-8 grid gap-6 lg:grid-cols-[1.5fr_1fr]">

        {/* Controls card */}
        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-2xl font-semibold text-white">Controls</h2>
            <span className={`rounded-full px-3 py-1 text-sm font-medium ${statusColor}`}>
              {status}
            </span>
          </div>

          <div className="grid gap-4">
            {/* File input */}
            <label className="flex flex-col gap-2 text-slate-200">
              Upload PCAP file
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng"
                onChange={handleFileChange}
                disabled={isAnalyzing}
                className="rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-200 disabled:opacity-50"
              />
            </label>

            {/* Buttons */}
            <div className="flex flex-col gap-3 sm:flex-row">
              <button
                onClick={handleStart}
                disabled={isAnalyzing || !selectedFile}
                className="inline-flex items-center justify-center gap-2 rounded-2xl bg-accent px-6 py-3 text-base font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isAnalyzing ? (
                  <>
                    <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                    Analysis Running...
                  </>
                ) : 'Start Analysis'}
              </button>
              <button
                onClick={handleResetFile}
                disabled={isAnalyzing}
                className="inline-flex items-center justify-center rounded-2xl border border-slate-700 bg-slate-900 px-6 py-3 text-base text-slate-200 transition hover:border-slate-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Reset
              </button>
            </div>

            {/* Progress bar (only while analyzing) */}
            {isAnalyzing && (
              <ProgressBar
                total={stats.total_packets}
                forwarded={stats.forwarded_packets}
                dropped={stats.dropped_packets}
              />
            )}

            {/* Blocking rules */}
            <div className="rounded-3xl border border-slate-700 bg-slate-900 p-4">
              <h3 className="text-lg font-semibold text-white">Blocking Rules</h3>
              <div className="mt-4 grid gap-4">
                {[
                  { type: 'app',    value: blockAppInput,    setter: setBlockAppInput,    placeholder: 'Block App (e.g. YouTube)' },
                  { type: 'ip',     value: blockIpInput,     setter: setBlockIpInput,     placeholder: 'Block IP (e.g. 192.168.1.50)' },
                  { type: 'domain', value: blockDomainInput, setter: setBlockDomainInput, placeholder: 'Block Domain (e.g. facebook.com)' }
                ].map(({ type, value, setter, placeholder }) => (
                  <div key={type} className="grid gap-2 sm:grid-cols-[1fr_auto]">
                    <input
                      value={value}
                      onChange={e => setter(e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && addRule(type)}
                      placeholder={placeholder}
                      disabled={isAnalyzing}
                      className="w-full rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100 disabled:opacity-50"
                    />
                    <button
                      onClick={() => addRule(type)}
                      disabled={isAnalyzing}
                      className="rounded-2xl bg-green-500 px-4 py-3 font-semibold text-slate-950 hover:bg-green-400 disabled:opacity-50"
                    >
                      Add
                    </button>
                  </div>
                ))}
              </div>

              {/* Rule tags */}
              <div className="mt-6 grid gap-3 rounded-3xl bg-slate-950 p-4">
                {[
                  { label: 'Blocked Apps',    type: 'app',    items: blockRules.apps },
                  { label: 'Blocked IPs',     type: 'ip',     items: blockRules.ips },
                  { label: 'Blocked Domains', type: 'domain', items: blockRules.domains }
                ].map(({ label, type, items }) => (
                  <div key={type}>
                    <p className="text-sm text-slate-400">{label}</p>
                    <div className="mt-2 flex flex-wrap gap-2">
                      {items.map(item => (
                        <button
                          key={item}
                          onClick={() => removeRule(type, item)}
                          disabled={isAnalyzing}
                          className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-200 transition hover:bg-rose-900 hover:text-rose-300 disabled:opacity-50"
                        >
                          {item} ×
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Download link */}
            {outputFile && (
              <div className="rounded-3xl border border-green-800 bg-green-950/40 p-4 text-slate-200">
                <p className="text-sm text-green-400">Output file ready</p>
                <a
                  href={`${API_BASE}/download/${outputFile}`}
                  className="mt-2 inline-block text-sky-400 underline"
                >
                  Download {outputFile}
                </a>
              </div>
            )}
          </div>
        </div>

        {/* Live Packet Logs */}
        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-2xl font-semibold text-white">Live Packet Logs</h2>
            {isAnalyzing && (
              <span className="flex items-center gap-1.5 rounded-full bg-sky-900 px-3 py-1 text-xs text-sky-300">
                <span className="h-2 w-2 animate-pulse rounded-full bg-sky-400" />
                Live
              </span>
            )}
          </div>
          <div className="h-[420px] overflow-y-auto rounded-3xl border border-slate-700 bg-slate-950 p-4 text-sm text-slate-300">
            {events.length === 0 ? (
              <p className="text-slate-500">Waiting for analysis events...</p>
            ) : (
              events.map((event, index) => (
                <div
                  key={`${event.ts}-${index}`}
                  className={`mb-3 border-b border-slate-800 pb-2 ${
                    event.message?.toLowerCase().includes('blocked') ? 'text-rose-400' :
                    event.message?.toLowerCase().includes('forwarded') ? 'text-green-400' :
                    'text-slate-300'
                  }`}
                >
                  <p className="text-xs text-slate-500">{new Date(event.ts).toLocaleTimeString()}</p>
                  <p className="font-mono text-xs">{event.message}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      {/* Stats cards */}
      <section className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Traffic Statistics</h2>
          <div className="mt-6 grid gap-4">
            <StatsCard label="Total Packets"  value={stats.total_packets}      color="text-white" />
            <StatsCard label="TCP Packets"    value={stats.tcp_packets}        color="text-sky-300" />
            <StatsCard label="UDP Packets"    value={stats.udp_packets}        color="text-cyan-300" />
            <StatsCard label="Forwarded"      value={stats.forwarded_packets}  color="text-green-300" />
            <StatsCard label="Dropped"        value={stats.dropped_packets}    color="text-rose-300" />
          </div>
        </div>

        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Application Breakdown</h2>
          <div className="mt-6 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={appDistributionData} dataKey="value" nameKey="name" outerRadius={100} label>
                  {appDistributionData.map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 12 }}
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Top Domains</h2>
          <div className="mt-6 space-y-3">
            {connections.top_domains.length === 0 ? (
              <p className="text-slate-500">No domains yet.</p>
            ) : (
              connections.top_domains.slice(0, 8).map(item => (
                <div key={item.domain} className="rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3">
                  <p className="truncate font-medium text-white">{item.domain}</p>
                  <p className="text-slate-400 text-sm">{item.count} packets</p>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      {/* Packet Distribution */}
      <section className="mt-6 rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-white">Packet Distribution</h2>
            <p className="text-slate-400">Forwarded vs dropped packet counts</p>
          </div>
          <div className="flex flex-wrap gap-4 text-sm text-slate-400">
            <span>Active connections: <span className="text-white">{connections.total_active_connections}</span></span>
            <span>Total seen: <span className="text-white">{connections.total_connections_seen}</span></span>
          </div>
        </div>
        <div className="mt-6 h-72 rounded-3xl bg-slate-950 p-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={packetDistributionData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #334155', borderRadius: 12 }}
              />
              <Legend />
              <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                <Cell fill="#34d399" />
                <Cell fill="#f87171" />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

    </div>
  );
}
