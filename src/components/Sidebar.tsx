import React from 'react';
import {
  LayoutDashboard,
  Search,
  FlaskConical,
  Sliders,
  Database,
  FileText,
  Code2,
  Lock,
  ExternalLink
} from 'lucide-react';

export type NavTab =
  | 'overview'
  | 'inspection'
  | 'testlab'
  | 'policies'
  | 'audit'
  | 'info'
  | 'code';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  auditCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  auditCount
}) => {
  const navItems = [
    {
      id: 'overview' as NavTab,
      label: 'Security Overview',
      icon: LayoutDashboard,
      badge: null
    },
    {
      id: 'inspection' as NavTab,
      label: 'Live Inspection',
      icon: Search,
      badge: 'Live'
    },
    {
      id: 'testlab' as NavTab,
      label: 'Security Test Lab',
      icon: FlaskConical,
      badge: '24 Cases'
    },
    {
      id: 'policies' as NavTab,
      label: 'Policy Management',
      icon: Sliders,
      badge: null
    },
    {
      id: 'audit' as NavTab,
      label: 'Audit Explorer',
      icon: Database,
      badge: auditCount > 0 ? String(auditCount) : null
    },
    {
      id: 'info' as NavTab,
      label: 'Security Information',
      icon: FileText,
      badge: null
    },
    {
      id: 'code' as NavTab,
      label: 'Python Codebase',
      icon: Code2,
      badge: 'pytest'
    }
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-slate-950 flex flex-col justify-between p-4 shrink-0">
      <div className="space-y-6">
        <div>
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-500 font-semibold px-3 mb-2">
            Gateway Navigation
          </div>
          <nav className="space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-950/70 text-cyan-300 border border-cyan-500/30 font-semibold shadow-sm shadow-cyan-950'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        isActive
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 text-xs">
          <div className="flex items-center gap-1.5 text-slate-300 font-semibold mb-1">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Gateway Boundary</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Untrusted text is inspected as raw data. Prompts violating blocking rules never reach the downstream AI model.
          </p>
        </div>
      </div>

      <div className="border-t border-slate-800/80 pt-3 text-[11px] font-mono text-slate-500 space-y-1">
        <div className="flex items-center justify-between">
          <span>Engine:</span>
          <span className="text-slate-300">Deterministic</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Storage:</span>
          <span className="text-slate-300">SQLite / Persistent</span>
        </div>
        <div className="flex items-center justify-between">
          <span>Streamlit:</span>
          <span className="text-slate-300">app.py Ready</span>
        </div>
      </div>
    </aside>
  );
};
