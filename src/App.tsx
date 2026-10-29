import React, { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { Sidebar, NavTab } from './components/Sidebar';
import { SecurityOverview } from './components/SecurityOverview';
import { LiveInspection } from './components/LiveInspection';
import { SecurityTestLab } from './components/SecurityTestLab';
import { PolicyManagement } from './components/PolicyManagement';
import { AuditExplorer } from './components/AuditExplorer';
import { SecurityInformation } from './components/SecurityInformation';
import { CodeBrowser } from './components/CodeBrowser';
import { PolicyRule, AuditEvent } from './types/gateway';
import { DEFAULT_POLICIES } from './lib/defaultPolicies';
import { SAMPLE_TEST_CASES } from './lib/sampleCases';
import {
  loadStoredAuditEvents,
  seedInitialAuditDemoEvents
} from './lib/auditStorage';

const POLICIES_STORAGE_KEY = 'ai_gateway_custom_policies_v1';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [policies, setPolicies] = useState<PolicyRule[]>(() => {
    try {
      const stored = localStorage.getItem(POLICIES_STORAGE_KEY);
      if (stored) {
        return JSON.parse(stored) as PolicyRule[];
      }
    } catch {}
    return DEFAULT_POLICIES;
  });

  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  // Initialize and load audit history on mount
  useEffect(() => {
    seedInitialAuditDemoEvents();
    const events = loadStoredAuditEvents();
    setAuditEvents(events);
  }, []);

  const refreshAuditEvents = () => {
    const updated = loadStoredAuditEvents();
    setAuditEvents(updated);
  };

  const handleSavePolicies = (updatedPolicies: PolicyRule[]) => {
    setPolicies(updatedPolicies);
    try {
      localStorage.setItem(POLICIES_STORAGE_KEY, JSON.stringify(updatedPolicies));
    } catch {}
  };

  const handleSeedDemoData = () => {
    seedInitialAuditDemoEvents();
    refreshAuditEvents();
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col antialiased">
      {/* Top Header */}
      <Navbar
        policies={policies}
        onOpenCodeBrowser={() => setActiveTab('code')}
      />

      {/* Main Container */}
      <div className="flex-1 flex overflow-hidden">
        {/* Navigation Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          auditCount={auditEvents.length}
        />

        {/* Dynamic Content Area */}
        <main className="flex-1 overflow-y-auto p-6 md:p-8 max-w-7xl mx-auto w-full">
          {activeTab === 'overview' && (
            <SecurityOverview
              auditEvents={auditEvents}
              onNavigateToInspection={() => setActiveTab('inspection')}
              onNavigateToTestLab={() => setActiveTab('testlab')}
              onSeedDemoData={handleSeedDemoData}
            />
          )}

          {activeTab === 'inspection' && (
            <LiveInspection
              policies={policies}
              sampleCases={SAMPLE_TEST_CASES}
              onInspectionComplete={refreshAuditEvents}
            />
          )}

          {activeTab === 'testlab' && (
            <SecurityTestLab
              policies={policies}
              sampleCases={SAMPLE_TEST_CASES}
            />
          )}

          {activeTab === 'policies' && (
            <PolicyManagement
              policies={policies}
              onSavePolicies={handleSavePolicies}
            />
          )}

          {activeTab === 'audit' && (
            <AuditExplorer
              events={auditEvents}
              onRefresh={refreshAuditEvents}
            />
          )}

          {activeTab === 'info' && <SecurityInformation />}

          {activeTab === 'code' && <CodeBrowser />}
        </main>
      </div>
    </div>
  );
}
