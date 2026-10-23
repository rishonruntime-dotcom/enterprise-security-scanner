import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Cpu } from 'lucide-react';
import api from '../lib/api';

const categoryColor: Record<string, string> = {
  framework: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  cms: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  server: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  language: 'bg-green-500/10 text-green-400 border-green-500/20',
  database: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
  cdn: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
};

export function Technologies() {
  const { data: techs = [], isLoading } = useQuery({
    queryKey: ['technologies'],
    queryFn: async () => (await api.get('/technologies')).data,
    refetchInterval: 30000,
  });

  const { data: categories = [] } = useQuery({
    queryKey: ['tech-categories'],
    queryFn: async () => (await api.get('/technologies/categories')).data,
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Technology Intelligence</h1>
        <p className="text-muted-foreground">All technologies detected across your attack surface.</p>
      </div>

      {/* Summary Stats */}
      <div className="grid gap-4 grid-cols-2 md:grid-cols-4">
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold">{techs.length}</div>
          <div className="text-xs text-muted-foreground mt-1">Total Technologies</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold">{categories.length}</div>
          <div className="text-xs text-muted-foreground mt-1">Categories</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold">{techs.filter((t: any) => t.version).length}</div>
          <div className="text-xs text-muted-foreground mt-1">With Version</div>
        </div>
        <div className="rounded-xl border border-border bg-card p-4 text-center">
          <div className="text-2xl font-bold">{new Set(techs.map((t: any) => t.target_url)).size}</div>
          <div className="text-xs text-muted-foreground mt-1">Unique Targets</div>
        </div>
      </div>

      {/* Technology Table */}
      <div className="rounded-xl border border-border bg-card shadow overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left">
              <th className="px-4 h-12 font-medium text-muted-foreground">Technology</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Category</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Version</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Detection Method</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Confidence</th>
              <th className="px-4 h-12 font-medium text-muted-foreground">Occurrences</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              <tr><td colSpan={6} className="p-4 text-center text-muted-foreground">Loading...</td></tr>
            ) : techs.length === 0 ? (
              <tr><td colSpan={6} className="p-8 text-center">
                <div className="flex flex-col items-center gap-2 text-muted-foreground">
                  <Cpu className="h-8 w-8" />
                  <p>No technologies detected yet. Run a scan to populate this inventory.</p>
                </div>
              </td></tr>
            ) : (
              techs.map((t: any) => (
                <tr key={t.id} className="border-b border-border hover:bg-muted/30">
                  <td className="px-4 py-3 font-medium flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-muted-foreground" />{t.name}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex rounded-full border px-2.5 py-0.5 text-xs font-medium ${categoryColor[t.category] || 'bg-secondary text-muted-foreground border-border'}`}>
                      {t.category}
                    </span>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{t.version || '—'}</td>
                  <td className="px-4 py-3">
                    {t.detection_methods && t.detection_methods.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {t.detection_methods.map((m: string) => (
                          <span key={m} className="inline-flex rounded-full border border-border/30 px-2 py-0.5 text-xs text-muted-foreground">{m}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">{t.detection_method || '—'}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-16 rounded-full bg-secondary overflow-hidden">
                        <div className="h-full bg-primary rounded-full" style={{ width: `${t.confidence * 100}%` }} />
                      </div>
                      <span className="text-xs text-muted-foreground">{(t.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{t.occurrence_count}×</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
