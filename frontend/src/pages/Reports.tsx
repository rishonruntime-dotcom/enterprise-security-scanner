import React, { useState } from 'react';
import { useMutation, useQuery } from '@tanstack/react-query';
import { FileText, Download, Loader2, CheckCircle2, ShieldAlert } from 'lucide-react';
import api from '../lib/api';

export function Reports() {
  const [reportResult, setReportResult] = useState<any>(null);
  const [selectedFormats, setSelectedFormats] = useState<string[]>(['pdf', 'html', 'json', 'sarif', 'md']);

  // Fetch scans to select
  const { data: scansData } = useQuery({
    queryKey: ['scans'],
    queryFn: async () => {
      const res = await api.get('/scans');
      return res.data;
    }
  });

  const scans = scansData || [];
  const [selectedScan, setSelectedScan] = useState<string>('');

  const generateReport = useMutation({
    mutationFn: async () => {
      if (!selectedScan) {
        throw new Error('Please select a scan.');
      }
      const res = await api.post('/reports', {
        formats: selectedFormats,
        scan_id: selectedScan
      });
      return res.data;
    },
    onSuccess: (data) => {
      setReportResult(data);
    }
  });

  const toggleFormat = (fmt: string) => {
    if (selectedFormats.includes(fmt)) {
      if (selectedFormats.length > 1) {
        setSelectedFormats(selectedFormats.filter(f => f !== fmt));
      }
    } else {
      setSelectedFormats([...selectedFormats, fmt]);
    }
  };

  const handleDownload = (format: string) => {
    if (!selectedScan) return;

    // Direct export API call using proper query formatting (?format=...&t=...)
    const exportUrl = `http://localhost:5000/api/v1/reports/${selectedScan}/export?format=${format}&t=${Date.now()}`;
    window.open(exportUrl, '_blank');
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight">Enterprise Reporting</h1>
        <p className="text-muted-foreground">Generate, view, and export executive security reports.</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Left Card: Configuration */}
        <div className="rounded-xl border border-border bg-card shadow-sm">
          <div className="p-6 border-b border-border">
            <h3 className="font-semibold text-lg flex items-center gap-2 text-foreground">
              <FileText className="h-5 w-5 text-primary" />
              Configure & Generate Report
            </h3>
          </div>
          <div className="p-6 space-y-6">
            <p className="text-sm text-muted-foreground">
              Compile scanner findings, technology inventory, and OWASP Top 10 compliance metrics into professional customer-ready reports.
            </p>

            {/* Scan Select */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">Select Scan Scope</label>
              <select
                value={selectedScan}
                onChange={(e) => setSelectedScan(e.target.value)}
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                <option value="">-- Select Completed Scan --</option>
                {scans.filter((s: any) => s.status.toLowerCase() === 'completed').map((s: any) => (
                  <option key={s.id} value={s.id}>
                    {s.target_url} ({new Date(s.completed_at || s.created_at).toLocaleString()})
                  </option>
                ))}
              </select>
            </div>

            {/* Formats Selection */}
            <div className="space-y-2.5">
              <label className="text-sm font-medium text-foreground">Report Export Formats</label>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { id: 'pdf', label: 'PDF Report' },
                  { id: 'html', label: 'HTML Report' },
                  { id: 'json', label: 'JSON Data' },
                  { id: 'sarif', label: 'SARIF Spec' },
                  { id: 'md', label: 'Markdown' }
                ].map((fmt) => {
                  const isChecked = selectedFormats.includes(fmt.id);
                  return (
                    <button
                      key={fmt.id}
                      onClick={() => toggleFormat(fmt.id)}
                      className={`flex items-center justify-center py-2 px-3 rounded-md text-xs font-semibold border transition-all ${isChecked
                        ? 'bg-primary/10 text-primary border-primary'
                        : 'bg-background text-muted-foreground border-border hover:bg-muted/30'
                        }`}
                    >
                      {fmt.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <button
              onClick={() => generateReport.mutate()}
              disabled={generateReport.isPending || !selectedScan}
              className="inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium ring-offset-background transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 bg-primary text-primary-foreground hover:bg-primary/90 h-10 px-4 py-2 w-full"
            >
              {generateReport.isPending ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Compiling Security Intelligence...
                </>
              ) : (
                'Generate Report Suite'
              )}
            </button>
          </div>
        </div>

        {/* Right Card: Status & Downloads */}
        <div className="rounded-xl border border-border bg-card shadow-sm flex flex-col justify-between">
          <div>
            <div className="p-6 border-b border-border">
              <h3 className="font-semibold text-lg text-foreground">
                Report Generation Status
              </h3>
            </div>

            <div className="p-6">
              {!reportResult ? (
                <div className="flex flex-col items-center justify-center py-12 text-center text-muted-foreground space-y-2">
                  <ShieldAlert className="h-10 w-10 text-muted-foreground/60" />
                  <p className="text-sm font-medium">No reports generated yet.</p>
                  <p className="text-xs">Configure your formats and click generate to download.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div className="flex items-center gap-2 text-emerald-400 bg-emerald-500/5 border border-emerald-500/10 rounded-lg p-4 mb-4">
                    <CheckCircle2 className="h-5 w-5 flex-shrink-0" />
                    <div>
                      <p className="text-sm font-semibold">Reports Compiled Successfully</p>
                      <p className="text-xs text-muted-foreground">Files are saved locally and available for download.</p>
                    </div>
                  </div>

                  {/* Discovery Quality Metrics */}
                  {reportResult.discovery_quality && (
                    <div className="border border-border/80 rounded-lg p-4 bg-card/50">
                      <h4 className="text-sm font-semibold text-foreground mb-3">Discovery Quality Metrics</h4>
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <span className="text-muted-foreground">Crawl Coverage:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.crawl_coverage_percent}%</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Forms Discovered:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.forms_discovered}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">APIs Discovered:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.apis_discovered}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">JS Files Analyzed:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.javascript_files_analyzed}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Hidden Endpoints:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.hidden_endpoints}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Assets Skipped:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.assets_skipped}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Third-Party Assets:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.third_party_assets}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Total Assets:</span>
                          <span className="ml-2 font-medium text-foreground">{reportResult.discovery_quality.total_assets}</span>
                        </div>
                      </div>
                    </div>
                  )}

                  <ul className="space-y-2.5">
                    {Object.keys(reportResult.files).map((format) => (
                      <li key={format} className="flex items-center justify-between border border-border/80 rounded-lg p-3 bg-card/50">
                        <div className="flex items-center gap-3">
                          <FileText className="h-5 w-5 text-primary" />
                          <div>
                            <p className="text-sm font-semibold uppercase">{format}</p>
                            <p className="text-xs text-muted-foreground">report.{format}</p>
                          </div>
                        </div>
                        <button
                          onClick={() => handleDownload(format)}
                          className="flex items-center gap-1.5 px-3 py-1.5 bg-secondary hover:bg-secondary/80 text-foreground hover:text-primary rounded-md text-xs font-semibold transition-colors"
                        >
                          <Download className="h-3.5 w-3.5" />
                          Download
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}