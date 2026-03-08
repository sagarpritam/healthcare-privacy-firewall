import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
    PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line
} from 'recharts';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const COLORS = ['#00C49F', '#FFBB28', '#FF8042', '#FF4444'];
const RISK_COLORS = { low: '#00C49F', medium: '#FFBB28', high: '#FF8042', critical: '#FF4444' };

function App() {
    const [metrics, setMetrics] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [testText, setTestText] = useState('');
    const [scanResult, setScanResult] = useState(null);
    const [scanning, setScanning] = useState(false);

    const fetchMetrics = async () => {
        try {
            const res = await axios.get(`${API_BASE}/analytics/dashboard`);
            setMetrics(res.data);
            setError(null);
        } catch (err) {
            setError('Failed to fetch metrics');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchMetrics();
        const interval = setInterval(fetchMetrics, 10000);
        return () => clearInterval(interval);
    }, []);

    const handleScan = async () => {
        if (!testText.trim()) return;
        setScanning(true);
        try {
            const res = await axios.post(`${API_BASE}/scan/text`, { text: testText });
            setScanResult(res.data);
        } catch (err) {
            setScanResult({ error: err.message });
        } finally {
            setScanning(false);
        }
    };

    if (loading) return <div style={styles.loading}>Loading dashboard...</div>;

    const overview = metrics?.overview || {};
    const scansByType = metrics?.scans_by_type || {};
    const scansByRisk = metrics?.scans_by_risk || {};
    const averages = metrics?.averages || {};

    const typeData = Object.entries(scansByType).map(([name, value]) => ({ name, value }));
    const riskData = Object.entries(scansByRisk).map(([name, value]) => ({ name, value, fill: RISK_COLORS[name] }));

    return (
        <div style={styles.container}>
            <header style={styles.header}>
                <h1 style={styles.title}>🛡️ Healthcare Privacy Firewall</h1>
                <p style={styles.subtitle}>Real-time Analytics Dashboard</p>
            </header>

            {error && <div style={styles.error}>{error}</div>}

            {/* Overview Cards */}
            <div style={styles.cardGrid}>
                <StatCard label="Total Scans" value={overview.total_scans} color="#3B82F6" />
                <StatCard label="Entities Detected" value={overview.total_entities_detected} color="#10B981" />
                <StatCard label="Alerts" value={overview.total_alerts} color="#F59E0B" />
                <StatCard label="Policy Violations" value={overview.policy_violations} color="#EF4444" />
                <StatCard label="Blocked" value={overview.blocked_requests} color="#8B5CF6" />
                <StatCard label="Avg Risk Score" value={averages.avg_risk_score} color="#EC4899" />
            </div>

            {/* Charts Row */}
            <div style={styles.chartRow}>
                <div style={styles.chartCard}>
                    <h3 style={styles.chartTitle}>Scans by Type</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <PieChart>
                            <Pie data={typeData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label>
                                {typeData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                            </Pie>
                            <Tooltip />
                            <Legend />
                        </PieChart>
                    </ResponsiveContainer>
                </div>

                <div style={styles.chartCard}>
                    <h3 style={styles.chartTitle}>Scans by Risk Level</h3>
                    <ResponsiveContainer width="100%" height={250}>
                        <BarChart data={riskData}>
                            <CartesianGrid strokeDasharray="3 3" />
                            <XAxis dataKey="name" />
                            <YAxis />
                            <Tooltip />
                            <Bar dataKey="value">
                                {riskData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                            </Bar>
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* Live Scanner */}
            <div style={styles.scannerCard}>
                <h3 style={styles.chartTitle}>🔍 Live Scanner</h3>
                <textarea
                    style={styles.textarea}
                    rows={4}
                    placeholder="Paste text to scan for PII/PHI... (e.g., 'Patient John Doe, SSN 123-45-6789, DOB 01/15/1980')"
                    value={testText}
                    onChange={(e) => setTestText(e.target.value)}
                />
                <button style={styles.scanBtn} onClick={handleScan} disabled={scanning}>
                    {scanning ? 'Scanning...' : 'Scan Text'}
                </button>
                {scanResult && (
                    <div style={styles.resultBox}>
                        <h4>Result</h4>
                        {scanResult.error ? (
                            <p style={{ color: '#EF4444' }}>{scanResult.error}</p>
                        ) : (
                            <>
                                <p><strong>Risk:</strong> {scanResult.risk_score}/100 ({scanResult.risk_level})</p>
                                <p><strong>Entities:</strong> {scanResult.entity_count}</p>
                                <p><strong>Policy:</strong> {scanResult.policy_result} {scanResult.should_block ? '🚫 BLOCKED' : '✅'}</p>
                                <p><strong>Masked Text:</strong></p>
                                <pre style={styles.pre}>{scanResult.masked_text}</pre>
                            </>
                        )}
                    </div>
                )}
            </div>

            {/* Recent Scans */}
            {metrics?.recent_scans?.length > 0 && (
                <div style={styles.tableCard}>
                    <h3 style={styles.chartTitle}>Recent Scans</h3>
                    <table style={styles.table}>
                        <thead>
                            <tr>
                                <th style={styles.th}>Time</th>
                                <th style={styles.th}>Type</th>
                                <th style={styles.th}>Risk</th>
                                <th style={styles.th}>Entities</th>
                                <th style={styles.th}>Policy</th>
                                <th style={styles.th}>Duration</th>
                            </tr>
                        </thead>
                        <tbody>
                            {metrics.recent_scans.slice(-10).reverse().map((scan, i) => (
                                <tr key={i} style={styles.tr}>
                                    <td style={styles.td}>{new Date(scan.timestamp).toLocaleTimeString()}</td>
                                    <td style={styles.td}>{scan.scan_type}</td>
                                    <td style={{ ...styles.td, color: RISK_COLORS[scan.risk_level] }}>
                                        {scan.risk_score} ({scan.risk_level})
                                    </td>
                                    <td style={styles.td}>{scan.entity_count}</td>
                                    <td style={styles.td}>{scan.policy_result}</td>
                                    <td style={styles.td}>{scan.processing_time_ms}ms</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}

function StatCard({ label, value, color }) {
    return (
        <div style={{ ...styles.statCard, borderTop: `4px solid ${color}` }}>
            <p style={styles.statLabel}>{label}</p>
            <p style={{ ...styles.statValue, color }}>{value ?? 0}</p>
        </div>
    );
}

const styles = {
    container: { maxWidth: 1200, margin: '0 auto', padding: 24, fontFamily: "'Inter', -apple-system, sans-serif", background: '#0F172A', minHeight: '100vh', color: '#E2E8F0' },
    header: { textAlign: 'center', marginBottom: 32 },
    title: { fontSize: 28, fontWeight: 700, color: '#F8FAFC', margin: 0 },
    subtitle: { color: '#94A3B8', fontSize: 14, margin: '4px 0 0' },
    loading: { textAlign: 'center', padding: 80, fontSize: 18, color: '#94A3B8' },
    error: { background: '#7F1D1D', color: '#FCA5A5', padding: 12, borderRadius: 8, marginBottom: 16, textAlign: 'center' },
    cardGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 16, marginBottom: 24 },
    statCard: { background: '#1E293B', borderRadius: 12, padding: 20, textAlign: 'center' },
    statLabel: { fontSize: 12, color: '#94A3B8', margin: '0 0 8px', textTransform: 'uppercase', letterSpacing: 1 },
    statValue: { fontSize: 28, fontWeight: 700, margin: 0 },
    chartRow: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 },
    chartCard: { background: '#1E293B', borderRadius: 12, padding: 20 },
    chartTitle: { fontSize: 16, fontWeight: 600, marginBottom: 16, color: '#F8FAFC' },
    scannerCard: { background: '#1E293B', borderRadius: 12, padding: 20, marginBottom: 24 },
    textarea: { width: '100%', padding: 12, borderRadius: 8, border: '1px solid #334155', background: '#0F172A', color: '#E2E8F0', fontSize: 14, resize: 'vertical', boxSizing: 'border-box' },
    scanBtn: { marginTop: 12, padding: '10px 24px', background: '#3B82F6', color: '#fff', border: 'none', borderRadius: 8, fontSize: 14, cursor: 'pointer', fontWeight: 600 },
    resultBox: { marginTop: 16, padding: 16, background: '#0F172A', borderRadius: 8, border: '1px solid #334155' },
    pre: { background: '#1E293B', padding: 12, borderRadius: 6, overflowX: 'auto', fontSize: 13, color: '#A5F3FC' },
    tableCard: { background: '#1E293B', borderRadius: 12, padding: 20 },
    table: { width: '100%', borderCollapse: 'collapse' },
    th: { textAlign: 'left', padding: '8px 12px', borderBottom: '1px solid #334155', color: '#94A3B8', fontSize: 12, textTransform: 'uppercase' },
    td: { padding: '8px 12px', borderBottom: '1px solid #1E293B', fontSize: 13 },
    tr: { transition: 'background 0.2s' },
};

export default App;
