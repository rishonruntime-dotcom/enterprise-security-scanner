import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Plus, Trash2, Globe, Loader2, CheckCircle2, Play } from 'lucide-react';
import api from '../lib/api';

export function Targets() {
  const qc = useQueryClient();
  const [form, setForm] = useState({ url: '', name: '', description: '', group: '' });
  const [error, setError] = useState('');

  const { data: targets = [], isLoading } = useQuery({
    queryKey: ['targets'],
    queryFn: async () => (await api.get('/targets')).data,
    refetchInterval: 15000,
  });

  const create = useMutation({
    mutationFn: (body: typeof form) => api.post('/targets', body),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['targets'] });
      setForm({ url: '', name: '', description: '', group: '' });
      setError('');
    },
    onError: (e: any) => setError(e.response?.data?.detail || 'Failed to create target'),
  });

  const remove = useMutation({
    mutationFn: (id: string) => api.delete(`/targets/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['targets'] }),
  });

  const startScan = useMutation({
    mutationFn: (url: string) => api.post('/scans', { target_url: url }),
    onSuccess: () => {
      // Could show a toast here, but we will redirect to /scans page 
      // or simply rely on the user navigating there.
      window.location.href = '/scans';
    }
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Target Management</h1>
        <p className="text-muted-foreground">Register and manage scan targets.</p>
      </div>

      {/* Add Target Form */}
      <div className="rounded-xl border border-border bg-card shadow p-6">
        <h3 className="font-semibold text-base mb-4 flex items-center gap-2"><Plus className="h-4 w-4" /> Add Target</h3>
        {error && <p className="text-destructive text-sm mb-3 p-2 bg-destructive/10 rounded">{error}</p>}
        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
          {['url', 'name', 'description', 'group'].map((field) => (
            <input
              key={field}
              placeholder={field.charAt(0).toUpperCase() + field.slice(1) + (field === 'url' ? ' (https://...)' : '')}
              value={(form as any)[field]}
              onChange={(e) => setForm((f) => ({ ...f, [field]: e.target.value }))}
              className="rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          ))}
        </div>
        <button
          onClick={() => create.mutate(form)}
          disabled={create.isPending || !form.url || !form.name}
          className="mt-3 inline-flex items-center gap-2 rounded-md bg-primary text-primary-foreground px-4 py-2 text-sm font-medium hover:bg-primary/90 disabled:opacity-50 disabled:pointer-events-none"
        >
          {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Add Target
        </button>
      </div>

      {/* Target Table */}
      <div className="rounded-xl border border-border bg-card shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="px-4 h-12 font-medium text-muted-foreground">Target</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">URL</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Group</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Scans</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Findings</th>
              <th className="px-4 h-12 font-medium text-muted-foreground"></th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={6} className="p-4 text-center text-muted-foreground">Loading...</td></tr>
            ) : targets.length === 0 ? (
              <tr><td colSpan={6} className="p-4 text-center text-muted-foreground">No targets registered yet.</td></tr>
            ) : (
              targets.map((t: any) => (
                <tr key={t.id} className="border-b border-border hover:bg-muted/50">
                  <td className="px-4 py-3 font-medium">
                    <div className="flex items-center gap-2">
                      <Globe className="h-4 w-4 text-muted-foreground" />
                      {t.name}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{t.url}</td>
                  <td className="px-4 py-3">
                    {t.group ? <span className="inline-flex rounded-full bg-secondary px-2 py-0.5 text-xs">{t.group}</span> : '—'}
                  </td>
                  <td className="px-4 py-3">{t.total_scans}</td>
                  <td className="px-4 py-3">{t.total_findings}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => startScan.mutate(t.url)}
                      disabled={startScan.isPending}
                      className="p-1.5 mr-2 rounded hover:bg-green-500/10 text-muted-foreground hover:text-green-500 transition-colors"
                      title="Start Scan"
                    >
                      <Play className="h-4 w-4" />
                    </button>
                    <button
                      onClick={() => remove.mutate(t.id)}
                      className="p-1.5 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive transition-colors"
                      title="Delete Target"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
