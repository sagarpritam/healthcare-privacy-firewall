import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
    ShieldAlert, ShieldCheck, ShieldBan, Activity, AlertTriangle,
    Database, Server, Shield
} from 'lucide-react';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip,
    ResponsiveContainer, AreaChart, Area
} from 'recharts';

const API_URL = 'http://localhost:8000';

function App() {
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const response = await axios.get(`${API_URL}/analytics/dashboard`);
                setData(response.data);
                setError(null);
            } catch (err) {
                setError('Failed to connect to gateway. Is the server running?');
                console.error(err);
            } finally {
                setLoading(false);
            }
        };

        fetchData();
        const interval = setInterval(fetchData, 3000);
        return () => clearInterval(interval);
    }, []);

    if (loading && !data) {
        return (
            <div className="flex items-center justify-center min-h-screen bg-gray-50">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
            </div>
        );
    }

    // Fallback empty metrics if error
    const metrics = data?.metrics || { total_scans: 0, total_alerts: 0, high_risk_payloads: 0, blocked_payloads: 0 };
    const TopEntities = data?.top_entities || [];

    // Dummy time series data for the area chart since the backend might not have time-series yet
    const riskTrendData = [
        { time: '10:00', score: 12 }, { time: '10:05', score: 45 },
        { time: '10:10', score: 20 }, { time: '10:15', score: 85 },
        { time: '10:20', score: 10 }, { time: '10:25', score: 100 },
    ];

    return (
        <div className="min-h-screen bg-gray-100 p-6">
            {/* Header */}
            <header className="flex justify-between items-center mb-8 bg-white p-4 rounded-xl shadow-sm">
                <div className="flex items-center gap-3">
                    <div className="p-3 bg-indigo-100 rounded-lg text-indigo-600">
                        <Shield size={28} />
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold text-gray-800">Healthcare Privacy Firewall</h1>
                        <p className="text-sm text-gray-500">Live API Traffic & Detection Analytics</p>
                    </div>
                </div>

                <div className="flex items-center gap-4">
                    <div className={`flex items-center gap-2 px-4 py-2 rounded-full text-sm font-semibold ${error ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'}`}>
                        <span className={`w-2 h-2 rounded-full ${error ? 'bg-red-600 animate-pulse' : 'bg-green-500'}`}></span>
                        {error ? 'Disconnected' : 'Connected'}
                    </div>
                </div>
            </header>

            {error && (
                <div className="mb-8 p-4 bg-red-50 border-l-4 border-red-500 text-red-700 flex items-center gap-2">
                    <AlertTriangle size={20} />
                    <p>{error}</p>
                </div>
            )}

            {/* KPI Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div className="bg-white p-6 rounded-xl shadow-sm flex items-center gap-4 border-l-4 border-blue-500">
                    <div className="p-3 bg-blue-100 text-blue-600 rounded-full"><Activity size={24} /></div>
                    <div>
                        <p className="text-sm text-gray-500 font-medium">Total Scans</p>
                        <h3 className="text-2xl font-bold text-gray-800">{metrics.total_scans}</h3>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm flex items-center gap-4 border-l-4 border-yellow-500">
                    <div className="p-3 bg-yellow-100 text-yellow-600 rounded-full"><AlertTriangle size={24} /></div>
                    <div>
                        <p className="text-sm text-gray-500 font-medium">High Risk Payloads</p>
                        <h3 className="text-2xl font-bold text-gray-800">{metrics.high_risk_payloads}</h3>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm flex items-center gap-4 border-l-4 border-red-500">
                    <div className="p-3 bg-red-100 text-red-600 rounded-full"><ShieldBan size={24} /></div>
                    <div>
                        <p className="text-sm text-gray-500 font-medium">Blocked by Policy</p>
                        <h3 className="text-2xl font-bold text-gray-800">{metrics.blocked_payloads}</h3>
                    </div>
                </div>

                <div className="bg-white p-6 rounded-xl shadow-sm flex items-center gap-4 border-l-4 border-green-500">
                    <div className="p-3 bg-green-100 text-green-600 rounded-full"><ShieldCheck size={24} /></div>
                    <div>
                        <p className="text-sm text-gray-500 font-medium">Alerts Fired</p>
                        <h3 className="text-2xl font-bold text-gray-800">{metrics.total_alerts}</h3>
                    </div>
                </div>
            </div>

            {/* Charts Section */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                {/* Entity Distribution */}
                <div className="bg-white p-6 rounded-xl shadow-sm">
                    <h3 className="text-lg font-bold text-gray-800 mb-6 flex items-center gap-2">
                        <Database size={20} className="text-indigo-500" />
                        Top Detected Entities
                    </h3>
                    <div className="h-64">
                        {TopEntities.length > 0 ? (
                            <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={TopEntities} layout="vertical" margin={{ top: 5, right: 30, left: 40, bottom: 5 }}>
                                    <CartesianGrid strokeDasharray="3 3" horizontal={false} />
                                    <XAxis type="number" />
                                    <YAxis dataKey="entity" type="category" width={100} tick={{ fontSize: 12 }} />
                                    <RechartsTooltip cursor={{ fill: '#f3f4f6' }} />
                                    <Bar dataKey="count" fill="#4f46e5" radius={[0, 4, 4, 0]} barSize={20} />
                                </BarChart>
                            </ResponsiveContainer>
                        ) : (
                            <div className="h-full flex items-center justify-center text-gray-400">No entities detected yet</div>
                        )}
                    </div>
                </div>

                {/* Risk Trend */}
                <div className="bg-white p-6 rounded-xl shadow-sm">
                    <h3 className="text-lg font-bold text-gray-800 mb-6 flex items-center gap-2">
                        <Activity size={20} className="text-indigo-500" />
                        Live Risk Score Trend
                    </h3>
                    <div className="h-64">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={riskTrendData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                                        <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="time" />
                                <YAxis domain={[0, 100]} />
                                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                                <RechartsTooltip />
                                <Area type="monotone" dataKey="score" stroke="#ef4444" fillOpacity={1} fill="url(#colorScore)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

        </div>
    );
}

export default App;
