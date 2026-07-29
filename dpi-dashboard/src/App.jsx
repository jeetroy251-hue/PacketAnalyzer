import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_URL;

console.log("API_BASE =", API_BASE);

function parseArrayField(value) {
  if (!value) return [];
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value);
    if (Array.isArray(parsed)) return parsed;
  } catch {
    return [value];
  }
  return [];
}

function StatsCard({ label, value, color }) {
  return (
    <div className="rounded-3xl bg-panel p-4 shadow-xl shadow-slate-900/30">
      <p className="text-slate-400 text-sm">{label}</p>
      <p className={`mt-3 text-3xl font-semibold ${color}`}>{value ?? 0}</p>
    </div>
  );
}

function App() {
  const fileInputRef = useRef(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus] = useState('idle');
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
  const [events, setEvents] = useState([]);
  const [packetDetails, setPacketDetails] = useState([]);
  const [outputFile, setOutputFile] = useState(null);
  const [blockAppInput, setBlockAppInput] = useState('');
  const [blockIpInput, setBlockIpInput] = useState('');
  const [blockDomainInput, setBlockDomainInput] = useState('');
  const [blockRules, setBlockRules] = useState({ apps: [], ips: [], domains: [] });
  const [activeTab, setActiveTab] = useState('stats');

  const appDistributionData = useMemo(() => {
    return Object.entries(connections.app_distribution || {})
      .map(([appType, count]) => ({ name: appType, value: count }))
      .sort((a, b) => b.value - a.value);
  }, [connections.app_distribution]);

  const packetDistributionData = useMemo(() => [
    { name: 'Forwarded', value: stats.forwarded_packets || 0 },
    { name: 'Dropped', value: stats.dropped_packets || 0 }
  ], [stats.forwarded_packets, stats.dropped_packets]);

  useEffect(() => {
    const initialize = async () => {
      await resetDashboard();
      fetchStats();
      fetchConnections();
    };

    const interval = setInterval(() => {
      fetchStats();
      fetchEvents();
      fetchConnections();
    }, 1000);

    initialize();

    return () => clearInterval(interval);
  }, []);

  async function fetchStats() {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      const json = await res.json();
      setStats(json.stats || {
        total_packets: 0,
        tcp_packets: 0,
        udp_packets: 0,
        forwarded_packets: 0,
        dropped_packets: 0
      });
      setOutputFile(json.outputFile || null);
      setStatus(json.status || 'idle');
    } catch (error) {
      console.error(error);
      setStats({
        total_packets: 0,
        tcp_packets: 0,
        udp_packets: 0,
        forwarded_packets: 0,
        dropped_packets: 0
      });
      setStatus('idle');
    }
  }

  async function fetchConnections() {
    try {
      const res = await fetch(`${API_BASE}/connections`);
      const json = await res.json();
      setConnections({
        total_active_connections: json.connections?.total_active_connections || 0,
        total_connections_seen: json.connections?.total_connections_seen || 0,
        top_domains: json.connections?.top_domains || [],
        app_distribution: json.connections?.app_distribution || {}
      });
    } catch (error) {
      console.error(error);
      setConnections({
        total_active_connections: 0,
        total_connections_seen: 0,
        top_domains: [],
        app_distribution: {}
      });
    }
  }

  async function fetchEvents() {
    try {
      const res = await fetch(`${API_BASE}/events`);
      const json = await res.json();
      setEvents((json.events || []).slice(-10).reverse());
      setPacketDetails(json.packet_details || []);
    } catch (error) {
      console.error(error);
      setEvents([]);
      setPacketDetails([]);
    }
  }

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];
    setSelectedFile(file || null);
  };

  const resetDashboard = async () => {
    setSelectedFile(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    setStatus('idle');
    setStats({
      total_packets: 0,
      tcp_packets: 0,
      udp_packets: 0,
      forwarded_packets: 0,
      dropped_packets: 0
    });
    setConnections({
      total_active_connections: 0,
      total_connections_seen: 0,
      top_domains: [],
      app_distribution: {}
    });
    setEvents([]);
    setPacketDetails([]);
    setOutputFile(null);
    setBlockAppInput('');
    setBlockIpInput('');
    setBlockDomainInput('');
    setBlockRules({ apps: [], ips: [], domains: [] });

    try {
      await fetch(`${API_BASE}/reset`, { method: 'POST' });
    } catch (error) {
      console.error('Failed to reset backend session:', error);
    }
  };

  const addRule = (type) => {
    if (type === 'app' && blockAppInput.trim()) {
      setBlockRules((prev) => ({ apps: [...prev.apps, blockAppInput.trim()], ips: prev.ips, domains: prev.domains }));
      setBlockAppInput('');
    }
    if (type === 'ip' && blockIpInput.trim()) {
      setBlockRules((prev) => ({ apps: prev.apps, ips: [...prev.ips, blockIpInput.trim()], domains: prev.domains }));
      setBlockIpInput('');
    }
    if (type === 'domain' && blockDomainInput.trim()) {
      setBlockRules((prev) => ({ apps: prev.apps, ips: prev.ips, domains: [...prev.domains, blockDomainInput.trim()] }));
      setBlockDomainInput('');
    }
  };

  const removeRule = (type, value) => {
    setBlockRules((prev) => ({
      apps: type === 'app' ? prev.apps.filter((item) => item !== value) : prev.apps,
      ips: type === 'ip' ? prev.ips.filter((item) => item !== value) : prev.ips,
      domains: type === 'domain' ? prev.domains.filter((item) => item !== value) : prev.domains
    }));
  };

  const handleStart = async () => {
    if (!selectedFile) {
      alert('Please upload a PCAP file first.');
      return;
    }

    const formData = new FormData();
    formData.append('pcap', selectedFile);
    formData.append('lbs', '2');
    formData.append('fpsPerLb', '4');
    formData.append('blockApps', JSON.stringify(blockRules.apps));
    formData.append('blockIps', JSON.stringify(blockRules.ips));
    formData.append('blockDomains', JSON.stringify(blockRules.domains));

    setStatus('starting');

    try {
      const response = await fetch(`${API_BASE}/start-analysis`, {
        method: 'POST',
        body: formData
      });
      const result = await response.json();
      if (result.success) {
        setStatus('completed');
        if (result.stats) setStats(result.stats);
        if (result.report) setConnections(result.report.connections || {});
        if (result.report?.events) setEvents(result.report.events.slice(-10).reverse());
        if (result.outputFile) setOutputFile(result.outputFile);
      } else {
        setStatus('failed');
        alert(result.error || 'Analysis failed.');
      }
    } catch (error) {
      setStatus('failed');
      alert(error.message);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 px-4 py-6 md:px-10">
      <header className="mb-8 rounded-3xl border border-slate-700 bg-panel/80 p-6 shadow-xl shadow-slate-900/40 backdrop-blur-sm">
        <h1 className="text-4xl font-semibold text-white">DPI Dashboard</h1>
        <p className="mt-2 max-w-2xl text-slate-400">
          Upload a PCAP file, then start the analysis to inspect traffic, block apps/domains/IPs, and view live statistics.
        </p>
      </header>

      <section className="mb-8 grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <h2 className="text-2xl font-semibold text-white">Controls</h2>
            <span className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-300">Status: {status}</span>
          </div>

          <div className="grid gap-4">
            <label className="flex flex-col gap-2 text-slate-200">
              Upload PCAP file
              <input
                ref={fileInputRef}
                type="file"
                accept=".pcap,.pcapng"
                onChange={handleFileChange}
                className="rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-200"
              />
            </label>

            <div className="flex flex-col gap-3 sm:flex-row">
              <button
                onClick={handleStart}
                className="inline-flex items-center justify-center rounded-2xl bg-accent px-6 py-3 text-base font-semibold text-slate-950 transition hover:bg-sky-400"
              >
                Start Analysis
              </button>
              <button
                onClick={resetDashboard}
                className="inline-flex items-center justify-center rounded-2xl border border-slate-700 bg-slate-900 px-6 py-3 text-base text-slate-200 transition hover:border-slate-500"
              >
                Reset File
              </button>
            </div>

            <div className="rounded-3xl border border-slate-700 bg-slate-900 p-4">
              <h3 className="text-lg font-semibold text-white">Blocking Rules</h3>
              <div className="mt-4 grid gap-4">
                <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                  <input
                    value={blockAppInput}
                    onChange={(e) => setBlockAppInput(e.target.value)}
                    placeholder="Block App (e.g. YouTube)"
                    className="w-full rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100"
                  />
                  <button onClick={() => addRule('app')} className="rounded-2xl bg-green-500 px-4 py-3 font-semibold text-slate-950 hover:bg-green-400">Add</button>
                </div>
                <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                  <input
                    value={blockIpInput}
                    onChange={(e) => setBlockIpInput(e.target.value)}
                    placeholder="Block IP (e.g. 192.168.1.50)"
                    className="w-full rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100"
                  />
                  <button onClick={() => addRule('ip')} className="rounded-2xl bg-green-500 px-4 py-3 font-semibold text-slate-950 hover:bg-green-400">Add</button>
                </div>
                <div className="grid gap-2 sm:grid-cols-[1fr_auto]">
                  <input
                    value={blockDomainInput}
                    onChange={(e) => setBlockDomainInput(e.target.value)}
                    placeholder="Block Domain (e.g. facebook.com)"
                    className="w-full rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3 text-slate-100"
                  />
                  <button onClick={() => addRule('domain')} className="rounded-2xl bg-green-500 px-4 py-3 font-semibold text-slate-950 hover:bg-green-400">Add</button>
                </div>
              </div>

              <div className="mt-6 grid gap-3 rounded-3xl bg-slate-950 p-4">
                <div>
                  <p className="text-sm text-slate-400">Blocked Apps</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {blockRules.apps.map((item) => (
                      <button
                        key={item}
                        onClick={() => removeRule('app', item)}
                        className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-200 transition hover:bg-slate-700"
                      >
                        {item} ×
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-sm text-slate-400">Blocked IPs</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {blockRules.ips.map((item) => (
                      <button
                        key={item}
                        onClick={() => removeRule('ip', item)}
                        className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-200 transition hover:bg-slate-700"
                      >
                        {item} ×
                      </button>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-sm text-slate-400">Blocked Domains</p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {blockRules.domains.map((item) => (
                      <button
                        key={item}
                        onClick={() => removeRule('domain', item)}
                        className="rounded-full bg-slate-800 px-3 py-1 text-sm text-slate-200 transition hover:bg-slate-700"
                      >
                        {item} ×
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {outputFile && (
              <div className="rounded-3xl border border-slate-700 bg-slate-900 p-4 text-slate-200">
                <p className="text-sm text-slate-400">Output file saved</p>
                <a href={`${API_BASE}/download/${outputFile}`} className="mt-2 inline-block text-accent underline">
                  Download {outputFile}
                </a>
              </div>
            )}
          </div>
        </div>

        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Live Packet Logs</h2>
          <div className="mt-4 h-[420px] overflow-y-auto rounded-3xl border border-slate-700 bg-slate-950 p-4 text-sm text-slate-300">
            {events.length === 0 ? (
              <p className="text-slate-500">Waiting for analysis events...</p>
            ) : (
              events.map((event, index) => (
                <div key={`${event.ts}-${index}`} className="mb-3 border-b border-slate-800 pb-2">
                  <p className="text-xs text-slate-500">{event.ts}</p>
                  <p>{event.message}</p>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-3">
        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Traffic Statistics</h2>
          <div className="mt-6 grid gap-4">
            <StatsCard label="Total Packets" value={stats.total_packets} color="text-white" />
            <StatsCard label="TCP Packets" value={stats.tcp_packets} color="text-sky-300" />
            <StatsCard label="UDP Packets" value={stats.udp_packets} color="text-cyan-300" />
            <StatsCard label="Forwarded" value={stats.forwarded_packets} color="text-green-300" />
            <StatsCard label="Dropped" value={stats.dropped_packets} color="text-rose-300" />
          </div>
        </div>

        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Application Breakdown</h2>
          <div className="mt-6 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={appDistributionData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" />
                <Tooltip wrapperStyle={{ backgroundColor: '#0f172a', borderRadius: 12, border: '1px solid #334155' }} />
                <Legend />
                <Bar dataKey="value" fill="#38bdf8" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
          <h2 className="text-2xl font-semibold text-white">Top Domains</h2>
          <div className="mt-6 space-y-3">
            {connections.top_domains.length === 0 ? (
              <p className="text-slate-500">No domains yet.</p>
            ) : (
              connections.top_domains.slice(0, 8).map((item) => (
                <div key={item.domain} className="rounded-2xl border border-slate-700 bg-slate-950 px-4 py-3">
                  <p className="font-medium text-white">{item.domain}</p>
                  <p className="text-slate-400">{item.count} packets</p>
                </div>
              ))
            )}
          </div>
        </div>
      </section>

      <section className="mt-6 rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-2xl font-semibold text-white">Packet Distribution</h2>
            <p className="text-slate-400">Forwarded vs dropped packet counts</p>
          </div>
          <div className="flex flex-wrap gap-3 text-sm text-slate-400">
            <span>Total connections: {connections.total_active_connections}</span>
            <span>Seen: {connections.total_connections_seen}</span>
          </div>
        </div>

        <div className="mt-6 h-72 rounded-3xl bg-slate-950 p-4">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={packetDistributionData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="name" stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" />
              <Tooltip wrapperStyle={{ backgroundColor: '#0f172a', borderRadius: 12, border: '1px solid #334155' }} />
              <Legend />
              <Bar dataKey="value" fill="#38bdf8" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </section>

      <section className="mt-6 rounded-3xl bg-panel p-6 shadow-xl shadow-slate-900/30">
        <div className="flex items-center justify-between gap-4">
          <div>
            <h2 className="text-2xl font-semibold text-white">Packet Details</h2>
            <p className="text-slate-400">Recent packet records with action and drop reason.</p>
          </div>
        </div>
        <div className="mt-6 overflow-x-auto rounded-3xl bg-slate-950 p-4">
          <table className="min-w-full border-collapse text-sm text-left text-slate-200">
            <thead>
              <tr className="border-b border-slate-700 text-slate-300">
                <th className="px-4 py-3">Packet No</th>
                <th className="px-4 py-3">Src IP</th>
                <th className="px-4 py-3">Dst IP</th>
                <th className="px-4 py-3">Protocol</th>
                <th className="px-4 py-3">App</th>
                <th className="px-4 py-3">Action</th>
                <th className="px-4 py-3">Dropped Reason</th>
              </tr>
            </thead>
            <tbody>
              {packetDetails.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-6 text-center text-slate-500">No packet details available.</td>
                </tr>
              ) : (
                packetDetails.slice(-20).reverse().map((packet) => (
                  <tr key={packet.packet_id} className="border-b border-slate-800">
                    <td className="px-4 py-3">{packet.packet_id}</td>
                    <td className="px-4 py-3">{packet.src_ip}</td>
                    <td className="px-4 py-3">{packet.dst_ip}</td>
                    <td className="px-4 py-3">{packet.protocol}</td>
                    <td className="px-4 py-3">{packet.app}</td>
                    <td className="px-4 py-3">{packet.action}</td>
                    <td className="px-4 py-3">{packet.reason || '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

export default App;
