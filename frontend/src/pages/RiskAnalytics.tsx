import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell, ResponsiveContainer, Legend
} from 'recharts';
import api from '../lib/api';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#3b82f6',
  Info: '#6b7280',
};

export function RiskAnalytics() {
  const { data: severity = {} } = useQuery({
    queryKey: ['analytics-severity'],
    queryFn: async () => (await api.get('/analytics/severity-breakdown')).data,
    refetchInterval: 30000,
  });

  const { data: trend = [] } = useQuery({
    queryKey: ['analytics-trend'],
    queryFn: async () => (await api.get('/analytics/findings-trend')).data,
    refetchInterval: 30000,
  });

  const { data: riskDist = [] } = useQuery({
    queryKey: ['analytics-risk'],
    queryFn: async () => (await api.get('/analytics/risk-distribution')).data,
    refetchInterval: 30000,
  });

  const { data: scanStatus = {} } = useQuery({
    queryKey: ['analytics-scan-status'],
    queryFn: async () => (await api.get('/analytics/scan-status')).data,
    refetchInterval: 15000,
  });

  const severityData = Object.entries(severity).map(([name, value]) => ({ name, value }));
  const scanStatusData = Object.entries(scanStatus).map(([name, value]) => ({ name, value }));
  const totalFindings = severityData.reduce((a, b) => a + (b.value as number), 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Risk Analytics</h1>
        <p className="text-muted-foreground">Trend analysis, severity distribution, and risk scoring.</p>
      </div>

      {/* KPI Row */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        {Object.entries(severity).map(([sev, count]) => (
          <div key={sev} className="rounded-xl border border-border bg-card p-4 text-center">
            <div className="text-2xl font-bold" style={{ color: SEVERITY_COLORS[sev] || '#fff' }}>{count as number}</div>
            <div className="text-xs text-muted-foreground mt-1">{sev}</div>
          </div>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Severity Pie */}
        <div className="rounded-xl border border-border bg-card shadow p-6">
          <h3 className="font-semibold text-base mb-4">Findings by Severity</h3>
          {severityData.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-10">No findings data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <PieChart>
                <Pie data={severityData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] || '#6b7280'} />
                  ))}
                </Pie>
                <Tooltip formatter={(v: any) => [`${v} (${((v / totalFindings) * 100).toFixed(0)}%)`, '']} contentStyle={{ background: '#1a1a2e', border: '1px solid #2d2d44' }} />
                <Legend wrapperStyle={{ fontSize: '12px' }} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Risk Distribution Bar */}
        <div className="rounded-xl border border-border bg-card shadow p-6">
          <h3 className="font-semibold text-base mb-4">Risk Score Distribution</h3>
          {riskDist.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-10">No risk data yet.</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={riskDist} margin={{ top: 5, right: 5, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2d2d44" />
                <XAxis dataKey="range" tick={{ fontSize: 11, fill: '#6b7280' }} />
                <YAxis tick={{ fontSize: 11, fill: '#6b7280' }} />
                <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #2d2d44' }} />
                <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Trend Chart */}
        <div className="rounded-xl border border-border bg-card shadow p-6 lg:col-span-2">
          <h3 className="font-semibold text-base mb-4">Findings Trend (30 days)</h3>
          {trend.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-10">No trend data yet. Findings are tracked by date as scans complete.</p>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <BarChart data={trend} margin={{ top: 5, right: 5, left: -10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#2d2d44" />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: '#6b7280' }} />
                <YAxis tick={{ fontSize: 11, fill: '#6b7280' }} />
                <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #2d2d44' }} />
                <Legend wrapperStyle={{ fontSize: '12px' }} />
                {['Critical', 'High', 'Medium', 'Low'].map((s) => (
                  <Bar key={s} dataKey={s} stackId="a" fill={SEVERITY_COLORS[s]} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  );
}
