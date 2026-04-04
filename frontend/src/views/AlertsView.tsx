import React, { useState, useEffect } from 'react';
import { 
  ShieldAlert, 
  Search, 
  Download, 
  CheckCircle2, 
  MapPin, 
  Network,
  Cpu,
  Info,
  Filter,
  Activity
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function AlertsView() {
  const [alerts, setAlerts] = useState<any[]>([]);

  useEffect(() => {
    const uStr = localStorage.getItem('dwtis_user');
    const queryParams = new URLSearchParams();
    if (uStr) {
      const u = JSON.parse(uStr);
      if (u.targetDomain) queryParams.append('domain', u.targetDomain);
      if (u.targetCompany) queryParams.append('company', u.targetCompany);
    }
    const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';

    // 1. Fetch initial historical alerts instantly
    fetch(`http://localhost:8000/api/alerts${qs}`)
      .then(r => r.json())
      .then(d => {
        if(d.status === 'success') {
          const standard = d.standard_alerts.map((a: any) => ({
            severity: a.severity || 'P2',
            timestamp: new Date(a.timestamp * 1000).toISOString().substr(11, 8),
            type: a.threat_type || 'Malware_Sign',
            pid: `ID_${a.id}`,
            message: a.message,
            entity: a.entity_id || 'Unknown',
            origin: 'External IP',
            icon: a.severity === 'P1' ? ShieldAlert : Info,
            color: a.severity === 'P1' ? 'text-error-neon' : 'text-primary-neon',
            bg: a.severity === 'P1' ? 'bg-error-neon/10' : 'bg-primary-neon/10',
            border: a.severity === 'P1' ? 'border-error-neon/20' : 'border-primary-neon/20',
          }));
          const correlation = d.correlation_alerts.map((a: any) => ({
            severity: 'CRITICAL',
            timestamp: new Date(a.timestamp * 1000).toISOString().substr(11, 8),
            type: 'CORRELATION_EVENT',
            pid: `CX_${a.id}`,
            message: a.description,
            entity: 'Cross-System',
            origin: 'Internal Correlation',
            icon: Activity,
            color: 'text-error-neon',
            bg: 'bg-error-neon/10',
            border: 'border-error-neon/20',
            accent: 'border-l-4 border-l-error-neon'
          }));
          setAlerts([...standard, ...correlation]);
        }
      })
      .catch(err => console.error("API Connection Error (Alerts):", err));

    // 2. Setup Server-Sent Events for Live Pushes
    const evtSource = new EventSource(`http://localhost:8000/api/alerts/stream${qs}`);
    evtSource.onmessage = (event) => {
      try {
        const liveEvent = JSON.parse(event.data);
        if(liveEvent.type === 'standard') {
           const a = liveEvent.data;
           const newAlert = {
              severity: a.severity,
              timestamp: new Date(a.timestamp * 1000).toISOString().substr(11, 8),
              type: a.threat_type || 'Malware_Sign',
              pid: `ID_${a.id}`,
              message: a.message,
              entity: a.entity_id || 'Unknown',
              origin: 'Live Push Vector',
              icon: a.severity === 'P1' ? ShieldAlert : Info,
              color: a.severity === 'P1' ? 'text-error-neon' : 'text-primary-neon',
              bg: a.severity === 'P1' ? 'bg-error-neon/10' : 'bg-primary-neon/10',
              border: a.severity === 'P1' ? 'border-error-neon/20' : 'border-primary-neon/20',
           };
           setAlerts(prev => [newAlert, ...prev]);
        } else if(liveEvent.type === 'correlation') {
           const a = liveEvent.data;
           const newAlert = {
              severity: 'CRITICAL',
              timestamp: new Date(a.timestamp * 1000).toISOString().substr(11, 8),
              type: 'CORRELATION_PUSH',
              pid: `CX_${a.id}`,
              message: a.description,
              entity: 'Cross-System',
              origin: 'Live Engine Correlation',
              icon: Activity,
              color: 'text-error-neon',
              bg: 'bg-error-neon/10',
              border: 'border-error-neon/20',
              accent: 'border-l-4 border-l-error-neon'
           };
           setAlerts(prev => [newAlert, ...prev]);
        }
      } catch (err) {}
    };

    return () => evtSource.close();
  }, []);

  return (
    <div className="space-y-10">
      <header className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6 relative z-10">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2 h-2 rounded-full bg-error-neon animate-pulse"></span>
            <span className="text-[10px] font-headline text-error-neon tracking-[0.3em] uppercase">PRIORITY_QUEUE: ACTIVE</span>
          </div>
          <h2 className="font-headline text-4xl font-bold tracking-tighter text-on-surface">SECURITY_ALERTS</h2>
          <p className="text-slate-500 font-headline text-sm mt-1">Real-time telemetry and intrusion detection logs.</p>
        </div>
        <div className="flex flex-wrap gap-4">
          <button className="bg-surface-container-high hover:bg-surface-bright text-on-surface px-4 py-2 rounded-md font-headline text-xs uppercase tracking-widest transition-all border border-outline-variant">
            Export_CSV
          </button>
          <button className="bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest px-6 py-2 rounded-md font-headline font-bold text-xs uppercase tracking-widest shadow-[0_0_20px_rgba(0,255,136,0.2)] hover:shadow-[0_0_30px_rgba(0,255,136,0.4)] transition-all">
            CLEAR_ACKNOWLEDGED
          </button>
        </div>
      </header>

      <div className="space-y-4 pb-20">
        {alerts.map((alert, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className={cn(
              "glass-panel group flex flex-col md:flex-row items-center gap-6 p-6 rounded-xl hover:bg-surface-bright/20 transition-all duration-300",
              alert.accent
            )}
          >
            <div className="flex items-center gap-6 w-full md:w-auto">
              <div className={cn(
                "flex flex-col items-center justify-center h-16 w-16 rounded-lg border",
                alert.bg, alert.border, alert.color
              )}>
                <alert.icon className="w-8 h-8" />
                <span className="text-[8px] font-bold tracking-tighter mt-1">{alert.severity}</span>
              </div>
              <div className="flex-1 min-w-[120px]">
                <div className="text-[10px] font-headline text-slate-500 tracking-wider">TIMESTAMP</div>
                <div className="text-sm font-headline text-on-surface">{alert.timestamp}</div>
              </div>
            </div>

            <div className="flex-1 w-full">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn("text-[10px] font-headline uppercase tracking-widest px-2 py-0.5 rounded", alert.bg, alert.color)}>
                  {alert.type}
                </span>
                {alert.pid && <span className="text-[10px] font-headline text-slate-500 uppercase tracking-widest">• {alert.pid}</span>}
              </div>
              <h3 className={cn("text-lg font-headline font-semibold", alert.severity === 'CRITICAL' ? "text-primary-neon" : "text-on-surface")}>
                {alert.message}
              </h3>
              <div className="flex items-center gap-4 mt-2">
                <div className="flex items-center gap-2">
                  <Network className="w-3 h-3 text-slate-500" />
                  <span className="text-xs font-headline text-slate-400">ENTITY: <span className="text-on-surface">{alert.entity}</span></span>
                </div>
                {alert.origin && (
                  <div className="flex items-center gap-2">
                    <MapPin className="w-3 h-3 text-slate-500" />
                    <span className="text-xs font-headline text-slate-400">ORIGIN: <span className="text-on-surface">{alert.origin}</span></span>
                  </div>
                )}
              </div>
            </div>

            <div className="flex gap-3 w-full md:w-auto justify-end">
              <button className="flex-1 md:flex-none px-4 py-2 bg-surface-container border border-outline-variant rounded text-[10px] font-bold tracking-widest text-slate-400 hover:text-primary-neon hover:border-primary-neon transition-all uppercase">Acknowledge</button>
              <button className={cn(
                "flex-1 md:flex-none px-4 py-2 rounded text-[10px] font-bold tracking-widest hover:brightness-110 transition-all uppercase",
                alert.severity === 'CRITICAL' ? "bg-error-neon text-surface-lowest" : "bg-surface-container-high text-on-surface border border-outline-variant"
              )}>
                Investigate
              </button>
            </div>
          </motion.div>
        ))}
      </div>

      <button className="fixed bottom-24 md:bottom-12 right-6 md:right-12 w-14 h-14 rounded-full bg-primary-neon text-surface-lowest flex items-center justify-center shadow-[0_0_30px_rgba(0,255,136,0.4)] hover:scale-110 transition-transform z-40">
        <Filter className="w-6 h-6" />
      </button>
    </div>
  );
}
