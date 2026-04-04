import React, { useState, useEffect } from 'react';
import { 
  TrendingUp, 
  AlertCircle, 
  Activity, 
  ShieldCheck, 
  ArrowUpRight, 
  Download,
  ArrowRight,
  Cpu,
  Database,
  SearchCode
} from 'lucide-react';
import { Ticker } from '@/src/components/Layout';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function DashboardView() {
  const [metrics, setMetrics] = useState<any[]>([
    { name: 'Raw Ingested', value: '...', trend: 'Syncing', icon: Activity, color: 'text-primary-neon' },
    { name: 'NLP Analyzed', value: '...', trend: 'Syncing', icon: Cpu, color: 'text-secondary-neon' },
    { name: 'Breaches Found', value: '...', trend: 'Syncing', icon: ShieldCheck, color: 'text-slate-400' },
    { name: 'Active Alerts', value: '...', trend: 'Syncing', icon: AlertCircle, color: 'text-error-neon', border: 'border-error-neon/20' },
  ]);
  
  const [activeMetric, setActiveMetric] = useState<string | null>(null);
  const [activeMetricData, setActiveMetricData] = useState<any[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [timeseries, setTimeseries] = useState<any[]>([]);

  const fetchDashboardData = () => {
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
            { name: 'Raw Ingested', value: d.stats.total_raw_collected, trend: 'DATA_STREAM_ACTIVE', icon: Database, color: 'text-primary-neon' },
            { name: 'NLP Analyzed', value: d.stats.total_nlp_processed, trend: 'THREAT_ENGINE_LOAD_42%', icon: Cpu, color: 'text-secondary-neon' },
            { name: 'Breaches Found', value: d.stats.total_breaches_found, trend: 'DB_LEAK_IDENTIFIED', icon: ShieldCheck, color: 'text-slate-400' },
            { name: 'Active Alerts', value: d.stats.total_alerts_generated, trend: 'ACTION_REQUIRED', icon: AlertCircle, color: 'text-error-neon', border: 'border-error-neon/20' },
          ]);
        }
      })
      .catch(err => console.error("API Connection Error (Stats): Ensure backend is running.", err));
      
    fetch(`http://localhost:8000/api/stats/timeseries${qs}`)
      .then(r => r.json())
      .then(d => {
          if (d.status === 'success') setTimeseries(d.series);
      })
      .catch(e => console.error(e));
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleMetricClick = (name: string) => {
    if (activeMetric === name) {
      setActiveMetric(null);
      return;
    }
    setActiveMetric(name);
    
    // Fetch underlying list data
    let endpoint = '';
    if (name === 'Raw Ingested') endpoint = '/api/posts/raw';
    else if (name === 'NLP Analyzed') endpoint = '/api/posts/analyzed';
    else if (name === 'Breaches Found') endpoint = '/api/breaches';
    else if (name === 'Active Alerts') endpoint = '/api/alerts';
    
    if (endpoint) {
      fetch(`http://localhost:8000${endpoint}?limit=10`)
        .then(r => r.json())
        .then(d => {
          if(d.status === 'success') {
            setActiveMetricData(d.posts || d.breaches || d.alerts || []);
            setExpandedId(null);
          }
        });
    }
  };

  // Helper to generate SVG path from timeseries
  const getGraphPath = () => {
    if(!timeseries.length) return "M0,300 L1000,300";
    const maxVal = Math.max(...timeseries.map(t => t.value), 10);
    const points = timeseries.map((t, i) => {
      const x = (i / (timeseries.length - 1)) * 1000;
      const y = 300 - (t.value / maxVal) * 260 - 20; // scale to 20-280px range
      return `${x},${y}`;
    });
    
    let d = `M${points[0].split(',')[0]},${points[0].split(',')[1]}`;
    for(let i = 1; i < points.length; i++) {
        const prev = points[i-1].split(',');
        const curr = points[i].split(',');
        const cp1x = parseFloat(prev[0]) + (parseFloat(curr[0]) - parseFloat(prev[0])) / 2;
        d += ` C${cp1x},${prev[1]} ${cp1x},${curr[1]} ${curr[0]},${curr[1]}`;
    }
    return d;
  };
  
  const graphPath = getGraphPath();

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
            onClick={() => handleMetricClick(m.name)}
            className={cn(
              "bg-surface-container rounded-xl p-6 shadow-xl relative overflow-hidden cursor-pointer transition-all hover:scale-[1.03] active:scale-95 group",
              m.border || "border border-outline-variant",
              activeMetric === m.name ? "ring-2 ring-primary-neon bg-surface-lowest scale-100" : ""
            )}
          >
            {m.name === 'High Severity' && <div className="absolute top-0 left-0 w-1 h-full bg-error-neon"></div>}
            <div className="flex justify-between items-start mb-4">
              <span className={cn(
                  "font-headline text-[10px] tracking-widest uppercase transition-colors",
                  activeMetric === m.name ? "text-primary-neon" : "text-slate-400 group-hover:text-slate-300"
              )}>{m.name}</span>
              <m.icon className={cn("w-5 h-5", m.color)} />
            </div>
            <div className="font-headline text-4xl font-bold text-on-surface mb-1">{m.value}</div>
            <div className={cn("flex items-center gap-1 text-[10px] uppercase tracking-tighter", m.color)}>
              {m.name === 'Total Threats' && <TrendingUp className="w-3 h-3" />}
              {m.trend}
            </div>
            {activeMetric === m.name && (
                <div className="absolute bottom-0 left-0 w-full h-1 bg-primary-neon animate-pulse"></div>
            )}
          </motion.div>
        ))}
      </div>

      <AnimatePresence>
        {activeMetric && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="bg-surface-container rounded-xl border border-primary-neon/30 overflow-x-auto shadow-[0_0_30px_rgba(0,255,136,0.05)]">
              <div className="p-4 border-b border-outline-variant bg-surface-highest/50 flex justify-between items-center">
                  <div className="font-headline text-xs font-bold text-primary-neon uppercase tracking-widest flex items-center gap-2">
                      <SearchCode className="w-4 h-4" />
                      Expanding Object: {activeMetric}
                  </div>
              </div>
              <table className="w-full text-left border-collapse min-w-[700px]">
                <thead>
                  <tr className="bg-surface-lowest border-b border-outline-variant">
                    <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">ID / Entity</th>
                    <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Data / Severity</th>
                    <th className="px-6 py-4 font-headline text-[10px] uppercase tracking-widest text-slate-400">Meta / Date</th>
                    <th className="px-6 py-4"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-outline-variant">
                  {activeMetricData.length === 0 && (
                      <tr><td colSpan={4} className="p-8 text-center text-slate-500 font-mono text-xs">Awaiting data sequence...</td></tr>
                  )}
                  {activeMetricData.map((row: any, i) => (
                    <React.Fragment key={i}>
                      <tr 
                        className={cn(
                          "transition-colors cursor-pointer group hover:bg-surface-bright/50",
                          expandedId === row.id ? "bg-surface-bright/80" : ""
                        )}
                        onClick={() => setExpandedId(expandedId === row.id ? null : row.id)}
                      >
                        <td className="px-6 py-4">
                          <code className="text-[10px] text-primary-neon bg-primary-neon/10 px-2 py-1 rounded block w-max mb-1">
                            {row.id || row.raw_id || 'UNKNOWN'}
                          </code>
                          <div className="text-xs text-on-surface font-medium truncate max-w-[200px]">
                            {row.entity || row.entity_value || row.source || row.threat_type || 'Generic Event'}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          {row.severity && (
                              <span className={cn(
                                "px-2 py-0.5 text-[9px] font-bold rounded uppercase tracking-tighter mb-1 inline-block",
                                (row.severity === 'Critical' || row.severity === 'P1') ? "bg-error-container/30 text-error-neon" :
                                (row.severity === 'Medium' || row.severity === 'P2') ? "bg-surface-highest text-secondary-neon" : "bg-surface-highest text-slate-500"
                              )}>
                                {row.severity}
                              </span>
                          )}
                          <div className="text-xs text-slate-400 truncate max-w-[300px]">
                              {row.message || row.fields || row.content || row.text || 'No data payload'}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                           <div className="text-[10px] text-slate-500 font-mono">
                               {row.date || row.discovered_at || row.created_at || (row.timestamp && new Date(row.timestamp * 1000).toLocaleString()) || 'Just now'}
                           </div>
                        </td>
                        <td className="px-6 py-4 text-right">
                          <ArrowRight className={cn(
                            "w-4 h-4 text-slate-500 group-hover:text-primary-neon inline-block transition-transform",
                            expandedId === row.id ? "rotate-90 text-primary-neon" : ""
                          )} />
                        </td>
                      </tr>
                      
                      {expandedId === row.id && (
                        <tr className="bg-[#0b0f14] border-b border-outline-variant">
                          <td colSpan={4} className="p-0">
                            <motion.div 
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              className="px-6 py-6 overflow-hidden"
                            >
                              <h4 className="text-[10px] uppercase tracking-widest text-primary-neon font-headline font-bold mb-3">RAW_TELEMETRY_PAYLOAD</h4>
                              <pre className="bg-[#05080a] border border-outline-variant rounded p-4 text-[11px] font-mono text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-96">
                                {JSON.stringify(row, null, 2)}
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
          </motion.div>
        )}
      </AnimatePresence>

      <div className="bg-surface-container rounded-xl p-8 border border-outline-variant shadow-2xl">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-8">
          <div>
            <h2 className="font-headline text-xl font-bold text-on-surface uppercase tracking-tight">Threat Propagation</h2>
            <p className="font-headline text-xs text-slate-500">Live network anomaly tracking over last 24 hours</p>
          </div>
          <div className="flex gap-2">
            <button className="px-3 py-1 bg-surface-bright text-[10px] rounded border border-outline-variant uppercase tracking-widest text-primary-neon shadow-[0_0_10px_rgba(0,255,136,0.1)]">Live</button>
            <button className="px-3 py-1 text-slate-400 text-[10px] rounded border border-outline-variant uppercase tracking-widest hover:text-on-surface transition-colors">History</button>
          </div>
        </div>
        
        <div className="w-full h-80 relative overflow-hidden group">
          <svg className="w-full h-full" preserveAspectRatio="none" viewBox="0 0 1000 300">
            <defs>
              <linearGradient id="areaGrad" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%" stopColor="#00FF88" stopOpacity="0.15" />
                <stop offset="100%" stopColor="#00FF88" stopOpacity="0" />
              </linearGradient>
            </defs>
            <path d={`${graphPath} L1000,300 L0,300 Z`} fill="url(#areaGrad)" className="transition-all duration-1000 ease-in-out" />
            <path d={graphPath} fill="none" stroke="#00FF88" strokeWidth="3" strokeLinecap="round" className="transition-all duration-1000 ease-in-out drop-shadow-[0_0_8px_rgba(0,255,136,0.8)]" />
            
            {timeseries.map((t, i) => {
                const x = (i / (timeseries.length - 1)) * 1000;
                const maxVal = Math.max(...timeseries.map(t => t.value), 10);
                const y = 300 - (t.value / maxVal) * 260 - 20;
                return (
                    <circle key={i} cx={x} cy={y} r="4" fill="#0E141A" stroke="#00FF88" strokeWidth="2" className="transition-all duration-1000 ease-in-out opacity-0 group-hover:opacity-100 hover:r-6 hover:fill-primary-neon" />
                );
            })}
          </svg>
          
          {timeseries.length > 0 && (
              <div className="absolute top-10 left-[75%] translate-x-1/2 p-3 glass-panel border border-primary-neon/20 rounded shadow-xl hidden lg:block pointer-events-none data-card">
                <div className="text-[10px] uppercase text-primary-neon mb-1 font-bold">Network Sweep Peak</div>
                <div className="text-xs text-on-surface">EVENTS/HR: {Math.max(...timeseries.map(t => t.value))}</div>
                <div className="text-[10px] text-slate-400">LAST_24_HR_CYCLE</div>
              </div>
          )}
        </div>
        
        <div className="flex justify-between mt-6 px-2">
          {timeseries.map((t, i) => {
              if (i % 6 === 0) {
                  return <span key={i} className="text-[10px] font-headline text-slate-500 tracking-widest uppercase">{t.time}</span>;
              }
              return null;
          })}
        </div>
      </div>
    </div>
  );
}
