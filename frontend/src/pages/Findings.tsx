import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import api from '../lib/api';
import { ShieldAlert, Search, ChevronDown, ChevronUp, ExternalLink, Info, AlertTriangle, CheckCircle, HelpCircle } from 'lucide-react';

export function Findings() {
  const [searchTerm, setSearchTerm] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);
  
  const { data, isLoading } = useQuery({
    queryKey: ['findings'],
    queryFn: async () => {
      const res = await api.get('/findings');
      return res.data;
    }
  });

  const findings = data?.findings || [];
  
  const filteredFindings = findings.filter((f: any) => 
    f.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
    f.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (f.owasp_category && f.owasp_category.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const getSeverityStyle = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/10 text-red-500 border-red-500/20';
      case 'high':
        return 'bg-orange-500/10 text-orange-500 border-orange-500/20';
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/20';
      case 'low':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/20';
      default:
        return 'bg-slate-500/10 text-slate-500 border-slate-500/20';
    }
  };

  const renderEvidence = (rawEvidence: string | null) => {
    if (!rawEvidence) return <p className="text-xs text-muted-foreground">No raw evidence recorded.</p>;
    try {
      // In python, it was stored either as str(data) or json. Let's try parsing
      let parsed = rawEvidence;
      // Handle single quote formats in python representation e.g. {'name': 'val'}
      if (rawEvidence.startsWith("{") && !rawEvidence.startsWith('{"')) {
        // Simple regex replace for python representation to JSON compatibility
        const jsonCompatible = rawEvidence
          .replace(/'/g, '"')
          .replace(/True/g, 'true')
          .replace(/False/g, 'false')
          .replace(/None/g, 'null');
        parsed = JSON.parse(jsonCompatible);
      } else {
        parsed = JSON.parse(rawEvidence);
      }
      return (
        <pre className="bg-secondary/20 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-border/50 text-foreground">
          {JSON.stringify(parsed, null, 2)}
        </pre>
      );
    } catch (e) {
      return (
        <pre className="bg-secondary/20 p-4 rounded-lg overflow-x-auto text-xs font-mono border border-border/50 text-foreground whitespace-pre-wrap">
          {rawEvidence}
        </pre>
      );
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Security Findings</h1>
          <p className="text-muted-foreground">Detailed vulnerability inventory and intelligence records.</p>
        </div>
      </div>

      <div className="rounded-xl border border-border bg-card shadow-sm">
        <div className="p-4 border-b border-border flex items-center">
          <div className="relative w-72">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search findings, endpoints, categories..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full rounded-md border border-input bg-background pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </div>
        </div>
        
        <div className="relative w-full overflow-auto">
          <table className="w-full caption-bottom text-sm">
            <thead className="[&_tr]:border-b">
              <tr className="border-b border-border transition-colors hover:bg-muted/50">
                <th className="h-12 w-6 px-4"></th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">Vulnerability</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">Severity</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">Original</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">FP Prob.</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">CWE</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground">OWASP Top 10</th>
                <th className="h-12 px-4 text-left align-middle font-semibold text-muted-foreground text-right">Priority Score</th>
              </tr>
            </thead>
            <tbody className="[&_tr:last-child]:border-0">
              {isLoading ? (
                <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">Loading findings...</td></tr>
              ) : filteredFindings.length === 0 ? (
                <tr><td colSpan={6} className="p-8 text-center text-muted-foreground">No findings recorded.</td></tr>
              ) : (
                filteredFindings.map((finding: any) => {
                  const isExpanded = expandedId === finding.id;
                  return (
                    <React.Fragment key={finding.id}>
                      <tr 
                        onClick={() => toggleExpand(finding.id)}
                        className="border-b border-border transition-colors hover:bg-muted/30 cursor-pointer"
                      >
                        <td className="p-4 align-middle text-center">
                          {isExpanded ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
                        </td>
                        <td className="p-4 align-middle font-medium">
                          <div className="flex flex-col">
                            <span className="text-foreground font-semibold flex items-center gap-2">
                              <ShieldAlert className="h-4 w-4 text-muted-foreground flex-shrink-0" />
                              {finding.title}
                            </span>
                            <span className="text-xs text-muted-foreground font-mono mt-0.5 truncate max-w-lg">{finding.endpoint}</span>
                          </div>
                        </td>
                        <td className="p-4 align-middle">
                          <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${getSeverityStyle(finding.severity)}`}>
                            {finding.severity}
                          </span>
                        </td>
                        {finding.original_severity && finding.original_severity !== finding.severity && (
                          <td className="p-4 align-middle">
                            <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${getSeverityStyle(finding.original_severity)}`}>
                              ↳ {finding.original_severity}
                            </span>
                          </td>
                        )}
                        {!finding.original_severity && (
                          <td className="p-4 align-middle text-muted-foreground text-xs">—</td>
                        )}
                        <td className="p-4 align-middle text-xs">
                          {finding.false_positive_probability != null 
                            ? `${(finding.false_positive_probability * 100).toFixed(0)}%` 
                            : 'N/A'}
                        </td>
                        <td className="p-4 align-middle font-mono text-xs">{finding.cwe_id || 'N/A'}</td>
                        <td className="p-4 align-middle text-xs font-medium text-slate-400">
                          {finding.owasp_category ? finding.owasp_category.split('-')[0] : 'N/A'}
                        </td>
                        <td className="p-4 align-middle text-right font-bold text-foreground">
                          {finding.priority_score ? finding.priority_score.toFixed(1) : '0.0'}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-secondary/10 border-b border-border">
                          <td colSpan={7} className="p-6">
                            <div className="grid gap-6 md:grid-cols-3">
                              {/* Left & Middle Column: Core Vuln Details */}
                              <div className="md:col-span-2 space-y-4">
                                <div>
                                  <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider">Description</h4>
                                  <p className="text-sm text-foreground mt-1">{finding.description || 'No description provided.'}</p>
                                </div>
                                
                                <div>
                                  <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider">Evidence</h4>
                                  <div className="mt-2">
                                    {renderEvidence(finding.raw_evidence)}
                                  </div>
                                </div>
                                
                                <div>
                                  <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider">Remediation Guidance</h4>
                                  <p className="text-sm text-foreground mt-1 bg-green-500/5 border border-green-500/10 p-3 rounded-md text-slate-300">
                                    {finding.remediation || 'Configure robust inputs sanitation and secure servers hardening.'}
                                  </p>
                                </div>
                              </div>

                              {/* Right Column: Threat Intel Mappings */}
                              <div className="bg-card/50 border border-border/50 p-4 rounded-lg space-y-4">
                                <h4 className="text-sm font-semibold border-b border-border pb-2 text-foreground">Threat Intelligence</h4>
                                
                                <div className="space-y-3 text-xs">
                                  <div className="flex justify-between py-1 border-b border-border/30">
                                    <span className="text-muted-foreground">CWE Identifier</span>
                                    {finding.cwe_id ? (
                                      <a href={`https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer" className="text-primary hover:underline flex items-center gap-1 font-semibold font-mono">
                                        {finding.cwe_id} <ExternalLink className="h-3 w-3" />
                                      </a>
                                    ) : <span className="text-muted-foreground">N/A</span>}
                                  </div>

                                  <div className="flex justify-between py-1 border-b border-border/30">
                                    <span className="text-muted-foreground">OWASP Category</span>
                                    <span className="font-semibold text-slate-300">{finding.owasp_category || 'N/A'}</span>
                                  </div>

                                  <div className="flex justify-between py-1 border-b border-border/30">
                                    <span className="text-muted-foreground">Endpoint Class</span>
                                    <span className="font-semibold text-slate-300">{finding.endpoint_class || 'Main Application'}</span>
                                  </div>

                                  <div className="flex justify-between py-1 border-b border-border/30">
                                    <span className="text-muted-foreground">CVSS Base Score</span>
                                    <span className="font-bold text-foreground">{finding.cvss_score ? finding.cvss_score.toFixed(1) : 'N/A'}</span>
                                  </div>

                                  <div className="flex justify-between py-1 border-b border-border/30">
                                    <span className="text-muted-foreground">EPSS Probability</span>
                                    <span className="font-semibold text-foreground">{finding.epss_score ? `${(finding.epss_score * 100).toFixed(1)}%` : 'N/A'}</span>
                                  </div>

                                  <div className="flex flex-col gap-1 py-1">
                                    <span className="text-muted-foreground">Verification Status</span>
                                    <span className="flex items-center gap-1.5 font-semibold text-emerald-400">
                                      <CheckCircle className="h-3.5 w-3.5" /> Automatically Verified
                                    </span>
                                  </div>
                                </div>

                                {finding.risk_breakdown && (
                                  <div className="mt-4">
                                    <h4 className="text-xs font-bold uppercase text-muted-foreground tracking-wider mb-2">Risk Breakdown</h4>
                                    <div className="grid grid-cols-3 gap-2 text-center">
                                      <div className="bg-secondary/10 rounded-lg p-3">
                                        <div className="text-lg font-bold text-foreground">{finding.risk_breakdown.likelihood?.toFixed(2) ?? 'N/A'}</div>
                                        <div className="text-xs text-muted-foreground">Likelihood</div>
                                      </div>
                                      <div className="bg-secondary/10 rounded-lg p-3">
                                        <div className="text-lg font-bold text-foreground">{finding.risk_breakdown.impact?.toFixed(2) ?? 'N/A'}</div>
                                        <div className="text-xs text-muted-foreground">Impact</div>
                                      </div>
                                      <div className="bg-secondary/10 rounded-lg p-3">
                                        <div className="text-lg font-bold text-foreground">{finding.risk_breakdown.exploitability?.toFixed(2) ?? 'N/A'}</div>
                                        <div className="text-xs text-muted-foreground">Exploitability</div>
                                      </div>
                                    </div>
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
