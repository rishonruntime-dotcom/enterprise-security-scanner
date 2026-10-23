import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { Activity, AlertTriangle, Shield, Target, Cpu, Clock, XCircle, CheckCircle, Eye, ShieldAlert, FileText } from 'lucide-react';
import api from '../lib/api';
import { Link } from 'react-router-dom';

export function Dashboard() {
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard-summary'],
    queryFn: async () => {
      const res = await api.get('/dashboard/summary');
      return res.data;
    },
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-8 bg-secondary rounded w-48"></div>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-secondary rounded-xl"></div>)}
        </div>
      </div>
    );
  }

  const scans = data?.scans || {};
  const findings = data?.findings || {};
  const recentScans = data?.recent_scans || [];
  const recentFindings = data?.recent_findings || [];

  const statCards = [
    { label: "Total Findings", value: findings.total ?? 0, icon: Shield, color: "text-foreground" },
    { label: "Critical Risks", value: findings.critical ?? 0, icon: AlertTriangle, color: "text-red-500" },
    { label: "Targets Scanned", value: data?.targets ?? 0, icon: Target, color: "text-blue-400" },
    { label: "Detected Technologies", value: data?.technologies ?? 0, icon: Cpu, color: "text-purple-400" },
  ];

  const statusIcon = (s: string) => {
    const map: Record<string, React.ReactNode> = {
      running: <Activity className="h-4 w-4 text-green-400 animate-pulse" />,
      completed: <CheckCircle className="h-4 w-4 text-green-500" />,
      failed: <XCircle className="h-4 w-4 text-destructive" />,
      cancelled: <XCircle className="h-4 w-4 text-muted-foreground" />,
      pending: <Clock className="h-4 w-4 text-yellow-400" />,
    };
    return map[s.toLowerCase()] ?? <Clock className="h-4 w-4 text-yellow-400" />;
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
      case 'high': return 'text-orange-500 bg-orange-500/10 border-orange-500/20';
      case 'medium': return 'text-yellow-500 bg-yellow-500/10 border-yellow-500/20';
      case 'low': return 'text-blue-500 bg-blue-500/10 border-blue-500/20';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Posture Dashboard</h1>
          <p className="text-muted-foreground">Automated vulnerability scans, threat intelligence, and compliance audit console.</p>
        </div>
        <Link 
          to="/reports" 
          className="flex items-center gap-1.5 px-4 py-2 bg-primary text-primary-foreground hover:bg-primary/90 text-sm font-semibold rounded-md transition-colors"
        >
          <FileText className="h-4 w-4" />
          Export Reports
        </Link>
      </div>

      {/* Main Stats Row */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((card) => (
          <div key={card.label} className="rounded-xl border border-border bg-card shadow-sm hover:shadow-md transition-all duration-200">
            <div className="p-6 flex flex-row items-center justify-between pb-2">
              <h3 className="tracking-tight text-sm font-medium text-muted-foreground">{card.label}</h3>
              <card.icon className={`h-5 w-5 ${card.color}`} />
            </div>
            <div className="p-6 pt-0">
              <div className={`text-3xl font-bold ${card.color}`}>{card.value}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Plugin Engine Activity Overview */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Active Scan Checks Card */}
        <div className="rounded-xl border border-border bg-card p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-lg text-foreground flex items-center gap-2">
                <Activity className="h-5 w-5 text-green-400" />
                Active Vulnerability Audits
              </h3>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-green-500/10 text-green-400 border border-green-500/20">
                DISCOVERED & ACTIVE
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              Direct testing of endpoints with automated fuzzing. Covers SQL Injection, Reflected XSS, and SSRF.
            </p>
          </div>
          <div className="flex items-end justify-between mt-6 pt-4 border-t border-border/50">
            <div>
              <div className="text-3xl font-bold text-foreground">{findings.active ?? 0}</div>
              <div className="text-xs text-muted-foreground">Confirmed Vulnerabilities</div>
            </div>
            <Link to="/findings" className="text-xs font-semibold text-primary hover:underline flex items-center gap-1">
              Inspect Active Findings <Eye className="h-3 w-3" />
            </Link>
          </div>
        </div>

        {/* Passive Checks Card */}
        <div className="rounded-xl border border-border bg-card p-6 shadow-sm flex flex-col justify-between">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-lg text-foreground flex items-center gap-2">
                <Shield className="h-5 w-5 text-blue-400" />
                Passive Configuration Checks
              </h3>
              <span className="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                CONTINUOUS ANALYSES
              </span>
            </div>
            <p className="text-xs text-muted-foreground">
              Response-header inspection, cookie configurations, verbose banner checking, and outdated script analysis.
            </p>
          </div>
          <div className="flex items-end justify-between mt-6 pt-4 border-t border-border/50">
            <div>
              <div className="text-3xl font-bold text-foreground">{findings.passive ?? 0}</div>
              <div className="text-xs text-muted-foreground">Misconfigurations Discovered</div>
            </div>
            <Link to="/findings" className="text-xs font-semibold text-primary hover:underline flex items-center gap-1">
              Inspect Passive Findings <Eye className="h-3 w-3" />
            </Link>
          </div>
        </div>
      </div>

      {/* Bottom Grid: Recent Scans, Vulnerabilities list, Risk Distribution */}
      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-7">
        
        {/* Recent Scans */}
        <div className="col-span-4 rounded-xl border border-border bg-card shadow-sm">
          <div className="p-6 border-b border-border">
            <h3 className="font-semibold text-base text-foreground">Recent Scan Actions</h3>
          </div>
          <div className="p-6 space-y-4">
            {recentScans.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">No scan actions recorded.</p>
            ) : (
              recentScans.map((scan: any) => (
                <div key={scan.id} className="flex items-center justify-between border-b border-border/40 pb-3 last:border-0 last:pb-0">
                  <div className="flex items-center gap-3">
                    {statusIcon(scan.status)}
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold truncate text-foreground">{scan.target_url}</p>
                      <p className="text-xs text-muted-foreground uppercase">{scan.status} — {scan.progress.toFixed(0)}%</p>
                    </div>
                  </div>
                  <div className="h-1.5 w-24 bg-secondary rounded-full overflow-hidden">
                    <div className="h-full bg-primary rounded-full" style={{ width: `${scan.progress}%` }} />
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Risk Distribution */}
        <div className="col-span-3 rounded-xl border border-border bg-card shadow-sm">
          <div className="p-6 border-b border-border">
            <h3 className="font-semibold text-base text-foreground">Risk Distribution</h3>
          </div>
          <div className="p-6 space-y-4">
            {[
              { label: "Critical", value: findings.critical ?? 0, total: findings.total || 1, bar: "bg-red-500" },
              { label: "High", value: findings.high ?? 0, total: findings.total || 1, bar: "bg-orange-500" },
              { label: "Medium", value: findings.medium ?? 0, total: findings.total || 1, bar: "bg-yellow-500" },
              { label: "Low", value: findings.low ?? 0, total: findings.total || 1, bar: "bg-blue-500" },
            ].map((item) => (
              <div key={item.label} className="space-y-1.5">
                <div className="flex justify-between text-xs font-semibold">
                  <span>{item.label}</span>
                  <span className="text-muted-foreground">{item.value}</span>
                </div>
                <div className="h-2 w-full rounded-full bg-secondary">
                  <div className={`h-full rounded-full ${item.bar} transition-all duration-500`}
                    style={{ width: `${(item.value / item.total) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Vulnerabilities List */}
      <div className="rounded-xl border border-border bg-card shadow-sm">
        <div className="p-6 border-b border-border">
          <h3 className="font-semibold text-base text-foreground">Recent Vulnerabilities Discovered</h3>
        </div>
        <div className="p-6 pt-0">
          <div className="space-y-3 mt-4">
            {recentFindings.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-6">No security findings reported.</p>
            ) : (
              recentFindings.map((finding: any) => (
                <div key={finding.id} className="flex items-center justify-between border-b border-border/40 pb-3 last:border-0 last:pb-0">
                  <div className="flex items-center gap-3">
                    <ShieldAlert className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-foreground truncate">{finding.title}</p>
                      <p className="text-xs text-muted-foreground truncate font-mono">{finding.endpoint}</p>
                    </div>
                  </div>
                  <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-2xs font-bold uppercase ${getSeverityColor(finding.severity)}`}>
                    {finding.severity}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
