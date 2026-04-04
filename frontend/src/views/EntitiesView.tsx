import React, { useState, useEffect } from 'react';
import { 
  PlusCircle, 
  Search, 
  Monitor, 
  ArrowRight, 
  Server as Dns, 
  Cloud, 
  Laptop, 
  Cpu,
  ChevronDown,
  Building2,
  Globe2,
  Mail,
  User,
  AlertTriangle
} from 'lucide-react';
import { Ticker } from '@/src/components/Layout';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function EntitiesView() {
  const [entities, setEntities] = useState<any[]>([]);

  useEffect(() => {
    const uStr = localStorage.getItem('dwtis_user');
    const queryParams = new URLSearchParams();
    if (uStr) {
      const u = JSON.parse(uStr);
      if (u.targetDomain) queryParams.append('domain', u.targetDomain);
      if (u.targetCompany) queryParams.append('company', u.targetCompany);
    }
    const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';

    fetch(`http://localhost:8000/api/entities${qs}`)
      .then(r => r.json())
      .then(d => {
        if(d.status === 'success' && d.entities) {
          const mapped = d.entities.map((e: any, i: number) => {
            const isDomain = e.name.includes('.');
            const isEmail = e.name.includes('@');
            return {
              name: e.name,
              id: `TGT-${String(i+1).padStart(4, '0')}`,
              ip: isDomain ? 'DNS Resolved Target' : 'Organization',
              type: isDomain ? 'DOMAIN' : isEmail ? 'EMAIL' : 'ENTITY',
              score: e.score || 0,
              status: e.status || 'AT_RISK',
              icon: isEmail ? Mail : (isDomain ? Globe2 : Building2),
              color: e.score > 7 ? 'text-error-neon' : e.score > 3 ? 'text-tertiary-fixed-dim' : 'text-primary-neon'
            };
          });
          setEntities(mapped);
        }
      })
      .catch(err => console.error(err));
  }, []);

  return (
    <div className="space-y-10">
      <Ticker />
      
      <header className="flex flex-col md:flex-row md:items-end justify-between gap-6">
        <div>
          <div className="text-[10px] tracking-[0.3em] uppercase text-primary-neon mb-2 font-headline">Asset Inventory</div>
          <h1 className="text-4xl md:text-5xl font-headline font-bold tracking-tight text-on-surface">ENTITIES_MANAGEMENT</h1>
        </div>
        <button className="bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest px-6 py-2.5 rounded-md font-headline font-bold text-sm tracking-tight flex items-center gap-2 transition-transform hover:scale-105 active:scale-95 shadow-[0_0_20px_rgba(0,255,136,0.2)]">
          <PlusCircle className="w-4 h-4" />
          NEW_NODE
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        <div className="md:col-span-6 relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-500 w-5 h-5" />
          <input 
            className="w-full recessed-input pl-12 pr-4 py-3 text-sm font-sans text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
            placeholder="SEARCH_ASSETS_BY_IP_OR_HOSTNAME..." 
            type="text"
          />
        </div>
        <div className="md:col-span-2">
          <select className="w-full recessed-input px-4 py-3 text-sm font-sans text-on-surface focus:ring-1 focus:ring-primary-neon appearance-none">
            <option>ALL_OS</option>
            <option>LINUX</option>
            <option>WINDOWS</option>
            <option>MACOS</option>
          </select>
        </div>
        <div className="md:col-span-2">
          <select className="w-full recessed-input px-4 py-3 text-sm font-sans text-on-surface focus:ring-1 focus:ring-primary-neon appearance-none">
            <option>ALL_STATUS</option>
            <option>ONLINE</option>
            <option>OFFLINE</option>
          </select>
        </div>
        <div className="md:col-span-2">
          <button className="w-full border border-outline-variant hover:bg-surface-bright transition-colors rounded-lg py-3 text-sm font-headline tracking-widest text-slate-400 uppercase">
            FILTERS
          </button>
        </div>
      </div>

      <div className="space-y-4">
        {entities.map((e, i) => (
          <motion.div 
            key={e.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.1 }}
            className="glass-panel rounded-xl p-6 group hover:border-primary-neon/20 transition-all flex flex-wrap lg:flex-nowrap items-center gap-8 relative overflow-hidden"
          >
            <div className="absolute inset-0 bg-gradient-to-r from-primary-neon/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none"></div>
            
            <div className="flex items-center gap-4 min-w-[240px]">
              <div className={cn(
                "w-12 h-12 rounded-lg bg-surface-lowest flex items-center justify-center border border-outline-variant group-hover:border-primary-neon/40 transition-colors",
                e.color
              )}>
                <e.icon className="w-6 h-6" />
              </div>
              <div>
                <div className="font-headline font-bold text-lg text-on-surface tracking-tight">{e.name}</div>
                <div className="text-[10px] tracking-widest uppercase text-slate-500">ID: {e.id}</div>
              </div>
            </div>

            <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-6">
              <div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">TARGET_TYPE</div>
                <div className="font-mono text-sm text-on-surface">{e.type}</div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">DATA_VECTOR</div>
                <div className="flex items-center gap-1.5 font-sans text-sm">
                  <TerminalIcon className="w-3 h-3" />
                  {e.ip}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">THREAT_FREQ_SCORE</div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 bg-surface-lowest rounded-full overflow-hidden">
                    <div 
                      className={cn("h-full", e.score > 7 ? "bg-error-neon" : e.score > 3 ? "bg-tertiary-fixed-dim" : "bg-primary-neon")} 
                      style={{ width: `${Math.min(100, e.score * 10)}%` }}
                    ></div>
                  </div>
                  <span className={cn(
                    "text-xs font-bold",
                    e.score > 7 ? "text-error-neon" : e.score > 3 ? "text-tertiary-fixed-dim" : "text-primary-neon"
                  )}>
                    {e.score.toFixed(1)}
                  </span>
                </div>
              </div>
              <div className="flex flex-col items-end lg:items-start">
                <div className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">MONITOR_STATUS</div>
                <span className={cn(
                  "px-2 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 bg-error-neon/10 text-error-neon"
                )}>
                  <span className="w-1.5 h-1.5 rounded-full bg-error-neon animate-pulse"></span>
                  {e.status}
                </span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button className="p-2 rounded-lg hover:bg-surface-bright text-slate-500 transition-colors">
                <Monitor className="w-5 h-5" />
              </button>
              <button className="p-2 rounded-lg hover:bg-surface-bright text-slate-500 transition-colors">
                <ArrowRight className="w-5 h-5 text-primary-neon" />
              </button>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="mt-12 flex justify-center">
        <button className="text-slate-500 font-headline text-xs tracking-[0.3em] uppercase flex items-center gap-2 hover:text-primary-neon transition-colors group">
          LOAD_MORE_RESOURCES
          <ChevronDown className="w-4 h-4 transition-transform group-hover:translate-y-1" />
        </button>
      </div>
    </div>
  );
}

import { Terminal as TerminalIcon } from 'lucide-react';
