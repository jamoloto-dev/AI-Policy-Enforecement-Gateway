import React, { useState } from 'react';
import {
  Database,
  Download,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  ShieldAlert,
  Clock,
  Layers,
  FileJson,
  FileSpreadsheet,
  X,
  Copy,
  Check
} from 'lucide-react';
import { AuditEvent, EnforcementAction, SeverityLevel } from '../types/gateway';
import {
  exportAuditToJson,
  exportAuditToCsv,
  clearAuditStorage
} from '../lib/auditStorage';

interface AuditExplorerProps {
  events: AuditEvent[];
  onRefresh: () => void;
}

export const AuditExplorer: React.FC<AuditExplorerProps> = ({ events, onRefresh }) => {
  const [decisionFilter, setDecisionFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);
  const [isCopied, setIsCopied] = useState<boolean>(false);

  // Filter events
  const filteredEvents = events.filter((ev) => {
    if (decisionFilter !== 'ALL' && ev.decision !== decisionFilter) return false;
    if (severityFilter !== 'ALL' && ev.riskLevel !== severityFilter) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      const inReq = ev.requestId.toLowerCase().includes(q);
      const inSnippet = ev.maskedSnippet.toLowerCase().includes(q);
      const inRules = ev.triggeredRules.toLowerCase().includes(q);
      const inCats = ev.categories.toLowerCase().includes(q);
      if (!inReq && !inSnippet && !inRules && !inCats) return false;
    }
    return true;
  });

  const handleDownloadJson = () => {
    const jsonStr = exportAuditToJson();
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gateway_audit_${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCsv = () => {
    const csvStr = exportAuditToCsv();
    const blob = new Blob([csvStr], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `gateway_audit_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClearHistory = () => {
    if (window.confirm('Are you sure you want to purge all persistent audit logs from local storage?')) {
      clearAuditStorage();
      onRefresh();
    }
  };

  const copyEventJson = () => {
    if (!selectedEvent) return;
    navigator.clipboard.writeText(JSON.stringify(selectedEvent, null, 2));
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Database className="w-5 h-5 text-cyan-400" />
            <span>Audit Explorer & Compliance Records</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Searchable, persistent SQLite inspection records. Masked previews protect secrets while maintaining cryptographic audit integrity.
          </p>
        </div>

        {/* Export buttons */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleDownloadJson}
            disabled={events.length === 0}
            className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs font-mono text-cyan-300 disabled:opacity-40 flex items-center gap-1.5 transition-all"
          >
            <FileJson className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
          <button
            onClick={handleDownloadCsv}
            disabled={events.length === 0}
            className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs font-mono text-cyan-300 disabled:opacity-40 flex items-center gap-1.5 transition-all"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={handleClearHistory}
            disabled={events.length === 0}
            className="p-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-rose-950/40 hover:border-rose-800/80 text-xs text-slate-400 hover:text-rose-300 disabled:opacity-40 transition-all"
            title="Clear all audit logs"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
        {/* Search */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search Request ID, snippet, or rule..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Decision Filter */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400 whitespace-nowrap">Decision:</span>
          <select
            value={decisionFilter}
            onChange={(e) => setDecisionFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Decisions</option>
            <option value="ALLOW">ALLOW</option>
            <option value="WARN">WARN</option>
            <option value="REDACT">REDACT</option>
            <option value="BLOCK">BLOCK</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-2">
          <span className="text-slate-400 whitespace-nowrap">Severity:</span>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800">
        <div className="flex items-center justify-between mb-3 text-xs font-mono text-slate-400">
          <span>Showing {filteredEvents.length} of {events.length} records</span>
          <span className="text-slate-500">Click any row to inspect details</span>
        </div>

        {filteredEvents.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            No audit records match your query or the database is empty.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="pb-2.5">TIMESTAMP (UTC)</th>
                  <th className="pb-2.5">REQUEST ID</th>
                  <th className="pb-2.5">VERDICT</th>
                  <th className="pb-2.5">RISK</th>
                  <th className="pb-2.5">RULES</th>
                  <th className="pb-2.5">CATEGORIES</th>
                  <th className="pb-2.5">MASKED PREVIEW</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredEvents.map((ev) => {
                  const decisionColors: Record<string, string> = {
                    ALLOW: 'text-emerald-400 bg-emerald-950/40 border-emerald-800/70',
                    WARN: 'text-amber-400 bg-amber-950/40 border-amber-800/70',
                    REDACT: 'text-cyan-400 bg-cyan-950/40 border-cyan-800/70',
                    BLOCK: 'text-rose-400 bg-rose-950/40 border-rose-800/70'
                  };

                  return (
                    <tr
                      key={ev.eventId}
                      onClick={() => setSelectedEvent(ev)}
                      className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 text-slate-400 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 text-slate-300 font-bold">{ev.requestId}</td>
                      <td className="py-2.5">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${decisionColors[ev.decision]}`}>
                          {ev.decision}
                        </span>
                      </td>
                      <td className="py-2.5 text-slate-200">
                        {ev.riskScore}/100
                      </td>
                      <td className="py-2.5 text-slate-300 max-w-[120px] truncate" title={ev.triggeredRules}>
                        {ev.triggeredRules || <span className="text-slate-600">--</span>}
                      </td>
                      <td className="py-2.5 text-slate-400 max-w-[120px] truncate" title={ev.categories}>
                        {ev.categories || <span className="text-slate-600">--</span>}
                      </td>
                      <td className="py-2.5 text-slate-400 max-w-xs truncate" title={ev.maskedSnippet}>
                        {ev.maskedSnippet}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Audit Detail Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2 font-mono text-sm font-bold text-slate-200">
                <Database className="w-4 h-4 text-cyan-400" />
                <span>Audit Event Record: {selectedEvent.eventId}</span>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div className="text-slate-500 text-[10px]">REQUEST ID</div>
                <div className="text-slate-200 font-bold mt-0.5">{selectedEvent.requestId}</div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div className="text-slate-500 text-[10px]">TIMESTAMP (UTC)</div>
                <div className="text-slate-200 font-bold mt-0.5">{selectedEvent.timestamp}</div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div className="text-slate-500 text-[10px]">DECISION & RISK</div>
                <div className="text-slate-200 font-bold mt-0.5">
                  {selectedEvent.decision} (Risk: {selectedEvent.riskScore}/100 - {selectedEvent.riskLevel})
                </div>
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80">
                <div className="text-slate-500 text-[10px]">LATENCY</div>
                <div className="text-slate-200 font-bold mt-0.5">{selectedEvent.executionTimeMs} ms</div>
              </div>
            </div>

            <div className="space-y-1 text-xs font-mono">
              <div className="text-slate-400 font-semibold">Masked Audit Snippet:</div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-slate-300 leading-relaxed select-all">
                {selectedEvent.maskedSnippet}
              </div>
            </div>

            {selectedEvent.redactedPreview && (
              <div className="space-y-1 text-xs font-mono">
                <div className="text-cyan-400 font-semibold">Redacted Output Preview:</div>
                <div className="p-3 bg-cyan-950/20 rounded-lg border border-cyan-800/40 text-cyan-200 leading-relaxed select-all">
                  {selectedEvent.redactedPreview}
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              <button
                onClick={copyEventJson}
                className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 flex items-center gap-1.5 transition-all"
              >
                {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{isCopied ? 'Copied' : 'Copy Event JSON'}</span>
              </button>

              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
