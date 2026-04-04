import React, { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  AlertCircle, 
  Activity, 
  ShieldCheck, 
  ArrowUpRight, 
  Download,
  ArrowRight,
  Cpu
} from 'lucide-react';
import { Ticker } from '@/src/components/Layout';
import { motion } from 'motion/react';

export function DashboardView() {
  const [metrics, setMetrics] = useState<any[]>([
    { name: 'Total Threats', value: '...', trend: 'Syncing', icon: Activity, color: 'text-primary-neon' },
    { name: 'High Severity', value: '...', trend: 'Syncing', icon: AlertCircle, color: 'text-error-neon', border: 'border-error-neon/20' },
    { name: 'Medium Severity', value: '...', trend: 'Syncing', icon: ShieldCheck, color: 'text-secondary-neon' },
    { name: 'Low Severity', value: '...', trend: 'Syncing', icon: ShieldCheck, color: 'text-slate-500' },
  ]);
  const [breachFeed, setBreachFeed] = useState<any[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    const uStr = localStorage.getItem('dwtis_user');
    const queryParams = new URLSearchParams();
    if (uStr) {
      const u = JSON.parse(uStr);
      if (u.targetDomain) queryParams.append('domain', u.targetDomain);
      if (u.targetCompany) queryParams.append('company', u.targetCompany);
    }
    const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';

    fetch(`http://localhost:8000/api/stats${qs}`)
      .then(r => r.json())
      .then(d => {
        if(d.status === 'success') {
          setMetrics([
            { name: 'Raw Ingested', value: d.stats.total_raw_collected, trend: 'DATA_STREAM_ACTIVE', icon: Activity, color: 'text-primary-neon' },
            { name: 'NLP Analyzed', value: d.stats.total_nlp_processed, trend: 'THREAT_ENGINE_LOAD_42%', icon: Cpu, color: 'text-secondary-neon' },
            { name: 'Breaches Found', value: d.stats.total_breaches_found, trend: 'DB_LEAK_IDENTIFIED', icon: ShieldCheck, color: 'text-slate-400' },
            { name: 'Active Alerts', value: d.stats.total_alerts_generated, trend: 'ACTION_REQUIRED', icon: AlertCircle, color: 'text-error-neon', border: 'border-error-neon/20' },
          ]);
        }
      })
      .catch(err => console.error("API Connection Error (Stats): Ensure backend is running.", err));
      
    fetch(`http://localhost:8000/api/breaches${qs}${qs ? '&' : '?'}limit=5`)
      .then(r => r.json())
      .then(d => {
         if(d.status === 'success') {
           setBreachFeed(d.breaches.map((b: any) => {
             let dataClasses = [];
             try {
               dataClasses = typeof b.data_classes === 'string' ? JSON.parse(b.data_classes) : b.data_classes;
             } catch(e) {}
             
             return {
               id: `BR-${b.id || 'N/A'}`,
               entity: b.database_name || 'Generic Leak',
               ip: 'TOR_HIDDEN_SERVICE',
               sourceApi: b.source_api || 'unknown',
               severity: 'Critical',
               fields: Array.isArray(dataClasses) ? dataClasses.join(', ') : 'Mixed Data',
               date: b.discovered_at || 'Unknown',
               rawJson: typeof b.raw_json === 'string' ? b.raw_json : JSON.stringify(b.raw_json, null, 2)
             };
           }));
         }
      })
      .catch(err => console.error("API Connection Error (Breaches): Ensure backend is running.", err));
  }, []);

  return (
    <div className="space-y-10">
      <header className="flex flex-col md:flex-row justify-between items-end md:items-center gap-6">
        <div>
          <div className="font-headline text-[10px] tracking-[0.3em] text-primary-neon uppercase mb-1">SYSTEM_STATUS: ACTIVE</div>
          <h1 className="font-headline text-4xl font-bold tracking-tight text-on-surface">Threat Dashboard</h1>
        </div>
        <button className="flex items-center gap-2 px-6 py-3 bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest rounded-md font-bold uppercase tracking-widest text-sm shadow-[0_0_20px_rgba(0,255,136,0.3)] hover:scale-[1.02] transition-transform">
          <Activity className="w-4 h-4" />
          Deploy Countermeasure
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {metrics.map((m, i) => (
          <motion.div 
            key={m.name}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className={`bg-surface-container rounded-xl p-6 border border-outline-variant shadow-xl relative overflow-hidden ${m.border}`}
          >
            {m.name === 'High Severity' && <div className="absolute top-0 left-0 w-1 h-full bg-error-neon"></div>}
            <div className="flex justify-between items-start mb-4">
              <span className="font-headline text-[10px] tracking-widest text-slate-400 uppercase">{m.name}</span>
              <m.icon className={cn("w-5 h-5", m.color)} />
            </div>
            <div className="font-headline text-4xl font-bold text-on-surface mb-1">{m.value}</div>
            <div className={cn("flex items-center gap-1 text-[10px] uppercase tracking-tighter", m.color)}>
              {m.name === 'Total Threats' && <TrendingUp className="w-3 h-3" />}
              {m.trend}
            </div>
          </motion.div>
        ))}
      </div>

      <div className="bg-surface-container rounded-xl p-8 border border-outline-variant shadow-2xl">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
          <div>
            <h2 className="font-headline text-xl font-bold text-on-surface uppercase tracking-tight">Threat Propagation</h2>
            <p className="font-headline text-xs text-slate-500">Live network anomaly tracking over last 24 hours</p>
          </div>
          <div className="flex gap-2">
            <button className="px-3 py-1 bg-surface-bright text-[10px] rounded border border-outline-variant uppercase tracking-widest text-primary-neon">Live</button>
            <button className="px-3 py-1 text-slate-400 text-[10px] rounded border border-outline-variant uppercase tracking-widest hover:text-on-surface">History</button>
          </div>
        </div>
        
        <div className="w-full h-80 relative overflow-hidden">
          <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 1000 300">
            <defs>
              <linearGradient id="areaGrad" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#00FF88" stopOpacity="0.1" />
                <stop offset="100%" stopColor="#00FF88" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d="M0,250 Q100,220 200,240 T400,100 T600,180 T800,40 T1000,60 L1000,300 L0,300 Z" fill="url(#areaGrad)" />
            <path d="M0,250 Q100,220 200,240 T400,100 T600,180 T800,40 T1000,60" fill="none" stroke="#00FF88" strokeWidth="3" strokeLinecap="round" />
            {[200, 400, 600, 800].map((x, i) => (
              <circle key={i} cx={x} cy={[240, 100, 180, 40][i]} r="4" fill="#0E141A" stroke="#00FF88" strokeWidth="2" />
            ))}
          </svg>
          
          <div className="absolute top-10 left-[75%] translate-x-1/2 p-3 glass-panel border border-primary-neon/20 rounded shadow-xl">
            <div className="text-[10px] uppercase text-primary-neon mb-1 font-bold">Anomaly Detected</div>
            <div className="text-xs text-on-surface">NODE: EN-SEC-04</div>
            <div className="text-[10px] text-slate-400">14:23:01 UTC</div>
          </div>
        </div>
        
        <div className="flex justify-between mt-6 px-2">
          {['00:00', '06:00', '12:00', '18:00'].map(t => (
            <span key={t} className="text-[10px] font-headline text-slate-500 tracking-widest uppercase">{t}</span>
          ))}
          <span className="text-[10px] font-headline text-primary-neon tracking-widest uppercase font-bold">Live</span>
        </div>
      </div>

      <section>
        <div className="flex justify-between items-center mb-6">
          <h2 className="font-headline text-xl font-bold text-on-surface uppercase tracking-tight">Active Breach Feed</h2>
          <button className="text-xs text-primary-neon uppercase tracking-widest hover:underline flex items-center gap-1">
            Export Report <Download className="w-3 h-3" />
          </button>
        </div>
        <div className="bg-surface-container rounded-xl border border-outline-variant overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[700px]">
            <thead>
              <tr className="bg-surface-lowest border-b border-outline-variant">
                <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Severity</th>
                <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Entity</th>
                <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Breach ID</th>
                <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Exposed Fields</th>
                <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Date</th>
                <th className="px-6 py-4"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-outline-variant">
              {breachFeed.map((b) => (
                <React.Fragment key={b.id}>
                  <tr 
                    className={cn(
                      "transition-colors cursor-pointer group",
                      expandedId === b.id ? "bg-surface-bright" : "hover:bg-surface-bright"
                    )}
                    onClick={() => setExpandedId(expandedId === b.id ? null : b.id)}
                  >
                    <td className="px-6 py-4">
                      <span className={cn(
                        "px-2 py-1 text-[10px] font-bold rounded uppercase tracking-tighter",
                        b.severity === 'Critical' ? "bg-error-container/30 text-error-neon" :
                        b.severity === 'Medium' ? "bg-surface-highest text-secondary-neon" : "bg-surface-highest text-slate-500"
                      )}>
                        {b.severity}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm font-medium text-on-surface">{b.entity}</div>
                      <div className="text-[10px] text-slate-500 font-mono">SRC: {b.sourceApi}</div>
                    </td>
                    <td className="px-6 py-4">
                      <code className="text-xs text-primary-neon font-mono bg-primary-neon/5 px-2 py-1 rounded">{b.id}</code>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400">{b.fields}</td>
                    <td className="px-6 py-4 text-xs text-slate-400">{b.date}</td>
                    <td className="px-6 py-4 text-right">
                      <ArrowRight className={cn(
                        "w-4 h-4 text-slate-500 group-hover:text-primary-neon inline-block transition-transform",
                        expandedId === b.id ? "rotate-90 text-primary-neon" : ""
                      )} />
                    </td>
                  </tr>
                  
                  {expandedId === b.id && (
                    <tr className="bg-[#0b0f14] border-b border-outline-variant">
                      <td colSpan={6} className="p-0">
                        <motion.div 
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          className="px-6 py-6 overflow-hidden"
                        >
                          <h4 className="text-[10px] uppercase tracking-widest text-primary-neon font-headline font-bold mb-3">RAW_TELEMETRY_PAYLOAD</h4>
                          <pre className="bg-[#05080a] border border-outline-variant rounded p-4 text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96">
                            {b.rawJson}
                          </pre>
                        </motion.div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

import { cn } from '@/src/lib/utils';
