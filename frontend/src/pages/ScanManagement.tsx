import React, { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Play, Square, Pause, Activity, CheckCircle, XCircle, Clock, Loader2 } from 'lucide-react';
import api from '../lib/api';

const statusColors: Record<string, string> = {
  running: 'text-green-400 bg-green-400/10 border-green-400/20',
  completed: 'text-blue-400 bg-blue-400/10 border-blue-400/20',
  failed: 'text-destructive bg-destructive/10 border-destructive/20',
  cancelled: 'text-muted-foreground bg-secondary border-border',
  pending: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20',
};

const StatusBadge = ({ status }: { status: string }) => (
  <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-medium ${statusColors[status] || 'text-muted-foreground'}`}>
    {status === 'running' && <Activity className="h-3 w-3 animate-pulse" />}
    {status === 'completed' && <CheckCircle className="h-3 w-3" />}
    {status === 'failed' && <XCircle className="h-3 w-3" />}
    {status === 'pending' && <Clock className="h-3 w-3" />}
    {status}
  </span>
);

export function ScanManagement() {
  const qc = useQueryClient();
  const [targetUrl, setTargetUrl] = useState('');
  const [logs, setLogs] = useState<string[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const logEnd = useRef<HTMLDivElement>(null);

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => (await api.get('/scans')).data,
    refetchInterval: 5000,
  });

  // WebSocket for live progress
  useEffect(() => {
    const ws = new WebSocket('ws://localhost:5000/ws');
    wsRef.current = ws;
    ws.onmessage = (e) => {
      const data = JSON.parse(e.data);
      if (data.type === 'scan.progress') {
        setLogs((prev) => [...prev.slice(-49), `[${new Date().toLocaleTimeString()}] ${data.payload.step || ''} — ${data.payload.progress?.toFixed(0)}%`]);
        qc.invalidateQueries({ queryKey: ['scans'] });
      }
      if (data.type === 'scan.completed') {
        setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ✓ Scan ${data.payload.scan_id} completed.`]);
        qc.invalidateQueries({ queryKey: ['scans'] });
      }
    };
    ws.onopen = () => {
      const interval = setInterval(() => ws.readyState === 1 && ws.send('ping'), 25000);
      return () => clearInterval(interval);
    };
    return () => ws.close();
  }, [qc]);

  useEffect(() => {
    logEnd.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const startScan = useMutation({
    mutationFn: (url: string) => api.post('/scans', { target_url: url, scan_type: 'full', profile: 'default' }),
    onSuccess: (res) => {
      setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] Started scan ${res.data.id} → ${res.data.target_url}`]);
      qc.invalidateQueries({ queryKey: ['scans'] });
      setTargetUrl('');
    },
  });

  const cancelScan = useMutation({
    mutationFn: (id: string) => api.post(`/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });

  const pauseScan = useMutation({
    mutationFn: (id: string) => api.post(`/scans/${id}/pause`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Scan Management</h1>
        <p className="text-muted-foreground">Start, monitor, and control vulnerability scans.</p>
      </div>

      {/* Start Scan */}
      <div className="rounded-xl border border-border bg-card shadow p-6">
        <h3 className="font-semibold text-base mb-4">Start New Scan</h3>
        <div className="flex gap-3">
          <input
            className="flex-1 rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
            placeholder="https://target.example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
          <button
            onClick={() => startScan.mutate(targetUrl)}
            disabled={startScan.isPending || !targetUrl}
            className="inline-flex items-center gap-2 rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:bg-primary/90 disabled:opacity-50"
          >
            {startScan.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Start Scan
          </button>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Scan Table */}
        <div className="rounded-xl border border-border bg-card shadow overflow-hidden">
          <div className="p-4 border-b border-border">
            <h3 className="font-semibold text-sm">Active & Recent Scans</h3>
          </div>
          <div className="overflow-auto max-h-[400px]">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-card">
                <tr className="border-b border-border text-left">
                  <th className="px-4 h-10 font-medium text-muted-foreground">Target</th>
                  <th className="px-4 h-10 font-medium text-muted-foreground">Status</th>
                  <th className="px-4 h-10 font-medium text-muted-foreground">Progress</th>
                  <th className="px-4 h-10 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">Loading...</td></tr>
                ) : scans.length === 0 ? (
                  <tr><td colSpan={4} className="p-4 text-center text-muted-foreground">No scans yet.</td></tr>
                ) : (
                  scans.map((scan: any) => (
                    <tr key={scan.id} className="border-b border-border hover:bg-muted/30">
                      <td className="px-4 py-3 max-w-[160px]">
                        <p className="truncate text-xs font-mono">{scan.target_url}</p>
                      </td>
                      <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-20 rounded-full bg-secondary overflow-hidden">
                            <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground">{scan.progress.toFixed(0)}%</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-1">
                          {scan.status === 'running' && (
                            <>
                              <button onClick={() => pauseScan.mutate(scan.id)} className="p-1 hover:bg-secondary rounded text-muted-foreground hover:text-foreground" title="Pause">
                                <Pause className="h-3.5 w-3.5" />
                              </button>
                              <button onClick={() => cancelScan.mutate(scan.id)} className="p-1 hover:bg-destructive/10 rounded text-muted-foreground hover:text-destructive" title="Cancel">
                                <Square className="h-3.5 w-3.5" />
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Live Log */}
        <div className="rounded-xl border border-border bg-card shadow overflow-hidden flex flex-col">
          <div className="p-4 border-b border-border flex items-center justify-between">
            <h3 className="font-semibold text-sm">Live Progress Log</h3>
            <span className="inline-flex items-center gap-1 text-xs text-green-400">
              <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse inline-block"></span>
              WebSocket
            </span>
          </div>
          <div className="bg-black/40 font-mono text-xs p-4 overflow-auto flex-1 max-h-[360px] space-y-1">
            {logs.length === 0 ? (
              <p className="text-muted-foreground">Waiting for scan events...</p>
            ) : (
              logs.map((l, i) => <p key={i} className="text-green-300">{l}</p>)
            )}
            <div ref={logEnd} />
          </div>
        </div>
      </div>
    </div>
  );
}
