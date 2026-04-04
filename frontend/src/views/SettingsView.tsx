import React from 'react';
import { 
  User, 
  Mail, 
  Key, 
  ShieldCheck, 
  RefreshCw, 
  Volume2, 
  Type, 
  Trash2, 
  ChevronRight,
  HelpCircle,
  Copy
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function SettingsView() {
  return (
    <div className="space-y-10">
      <header className="mb-12">
        <div className="flex justify-between items-end">
          <div>
            <h1 className="font-headline text-5xl font-bold tracking-tighter text-on-surface mb-2">SYSTEM_SETTINGS</h1>
            <p className="text-slate-500 font-headline tracking-[0.2em] text-xs uppercase">Node ID: BS-OP-240-GAMMA | Last Sync: 02:45 UTC</p>
          </div>
          <div className="hidden sm:block text-right">
            <span className="text-[10px] text-primary-neon block font-headline tracking-widest">STATUS: SECURE</span>
            <div className="h-1 w-32 bg-surface-container mt-2 rounded-full overflow-hidden">
              <div className="h-full bg-primary-neon w-3/4"></div>
            </div>
          </div>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        <section className="md:col-span-7 glass-panel rounded-xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <h2 className="font-headline text-xl font-semibold flex items-center gap-3">
              <User className="w-5 h-5 text-primary-neon" />
              PROFILE_METADATA
            </h2>
            <span className="text-[10px] text-slate-500 font-headline tracking-widest">CORE_IDENTITY</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">Operator Name</label>
              <input className="w-full recessed-input text-on-surface p-3 font-mono text-sm" type="text" defaultValue="ALEX_REID_01" />
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">Assigned Email</label>
              <input className="w-full recessed-input text-on-surface p-3 font-mono text-sm" type="email" defaultValue="reid@breachsight.io" />
            </div>
            <div className="sm:col-span-2 space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">Bio / Authorization Note</label>
              <textarea className="w-full recessed-input text-on-surface p-3 font-mono text-sm min-h-[100px]" defaultValue="Lead Threat Analyst specializing in zero-day exploit detection and network forensic investigation." />
            </div>
          </div>
          <div className="mt-8 flex justify-end">
            <button className="bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest font-headline text-xs font-bold uppercase tracking-widest py-3 px-8 rounded-lg hover:scale-[1.02] transition-transform shadow-xl">
              Update Core Profile
            </button>
          </div>
        </section>

        <section className="md:col-span-5 glass-panel rounded-xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <h2 className="font-headline text-xl font-semibold flex items-center gap-3">
              <Key className="w-5 h-5 text-primary-neon" />
              API_ACCESS
            </h2>
            <HelpCircle className="w-5 h-5 text-slate-500 cursor-pointer hover:text-primary-neon transition-colors" />
          </div>
          <div className="space-y-6">
            {[
              { label: 'Production Key', key: 'BS_LIVE_********************4X2Y', status: 'Active' },
              { label: 'Testing / Sandbox', key: 'BS_TEST_********************9A01', status: 'Staging' }
            ].map((item) => (
              <div key={item.label} className="p-4 bg-surface-lowest rounded-lg border border-outline-variant relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <Copy className="w-3 h-3 text-primary-neon cursor-pointer" />
                </div>
                <label className="text-[9px] text-slate-500 uppercase tracking-widest font-headline block mb-1">{item.label}</label>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-on-surface tracking-tighter">{item.key}</span>
                  <span className={cn(
                    "text-[9px] px-2 py-0.5 rounded uppercase",
                    item.status === 'Active' ? "bg-secondary-container/20 text-secondary-neon" : "bg-surface-bright text-slate-400"
                  )}>{item.status}</span>
                </div>
              </div>
            ))}
            <button className="w-full border border-primary-neon/30 text-primary-neon font-headline text-[10px] font-bold uppercase tracking-widest py-3 rounded-lg hover:bg-primary-neon/5 transition-all flex items-center justify-center gap-2">
              <RefreshCw className="w-3 h-3" />
              Generate New Node Key
            </button>
          </div>
        </section>

        <section className="md:col-span-6 glass-panel rounded-xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <h2 className="font-headline text-xl font-semibold flex items-center gap-3">
              <ShieldCheck className="w-5 h-5 text-primary-neon" />
              SECURITY_PROTOCOL
            </h2>
          </div>
          <div className="space-y-6">
            {[
              { title: 'Multi-Factor Authentication', desc: 'Require biometric or TOTP for every login.', active: true },
              { title: 'Session Auto-Terminate', desc: 'Log out after 15 minutes of inactivity.', active: false },
            ].map((item) => (
              <div key={item.title} className="flex items-center justify-between p-4 bg-surface-container rounded-lg">
                <div>
                  <h3 className="text-sm font-semibold text-on-surface">{item.title}</h3>
                  <p className="text-xs text-slate-500">{item.desc}</p>
                </div>
                <button className={cn(
                  "w-11 h-6 rounded-full transition-all relative",
                  item.active ? "bg-primary-neon" : "bg-surface-highest"
                )}>
                  <div className={cn(
                    "w-5 h-5 bg-white rounded-full absolute top-0.5 transition-all",
                    item.active ? "left-5.5" : "left-0.5"
                  )}></div>
                </button>
              </div>
            ))}
            <div className="flex items-center justify-between p-4 bg-surface-container rounded-lg">
              <div>
                <h3 className="text-sm font-semibold text-on-surface">IP Access Whitelist</h3>
                <p className="text-xs text-slate-500">Restrict access to registered network nodes.</p>
              </div>
              <button className="text-[10px] text-primary-neon font-headline uppercase tracking-widest flex items-center gap-1">
                Configure <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </section>

        <section className="md:col-span-6 glass-panel rounded-xl p-8 shadow-2xl">
          <div className="flex items-center justify-between mb-8">
            <h2 className="font-headline text-xl font-semibold flex items-center gap-3">
              <RefreshCw className="w-5 h-5 text-primary-neon" />
              SYSTEM_PREFS
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">UI Refresh Rate</label>
              <select className="w-full bg-surface-lowest text-on-surface border-none rounded-lg p-3 focus:ring-1 focus:ring-primary-neon transition-all font-mono text-sm appearance-none">
                <option>Real-time (0.5s)</option>
                <option selected>Optimized (2.0s)</option>
                <option>Battery Saver (10s)</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">Alert Sound Profile</label>
              <select className="w-full bg-surface-lowest text-on-surface border-none rounded-lg p-3 focus:ring-1 focus:ring-primary-neon transition-all font-mono text-sm appearance-none">
                <option>Tactical Silenced</option>
                <option>Critical Audible</option>
                <option selected>Visual Only</option>
              </select>
            </div>
            <div className="sm:col-span-2 space-y-2">
              <label className="text-[10px] text-slate-400 uppercase tracking-widest font-headline ml-1">Terminal Font Size</label>
              <div className="flex items-center gap-4 py-2">
                <span className="text-[10px] text-slate-500 uppercase">Compact</span>
                <input className="flex-1 accent-primary-neon h-1 bg-surface-highest rounded-lg appearance-none cursor-pointer" type="range" />
                <span className="text-[10px] text-slate-500 uppercase">Expanded</span>
              </div>
            </div>
          </div>
          <div className="mt-8 pt-8 border-t border-outline-variant flex justify-between items-center">
            <span className="text-[10px] text-slate-500 uppercase tracking-widest">Environment: Production_Node_Alpha</span>
            <button className="text-[10px] text-error-neon font-headline uppercase tracking-widest flex items-center gap-1 hover:underline">
              <Trash2 className="w-3 h-3" /> Reset Defaults
            </button>
          </div>
        </section>
      </div>
    </div>
  );
}
