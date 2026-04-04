import React, { useState, useEffect } from 'react';
import { 
  PlusCircle, 
  Download, 
  FileText, 
  Database, 
  Search,
  CheckCircle2,
  Clock
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function ReportsView() {
  const [reports, setReports] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const uStr = localStorage.getItem('dwtis_user');
    const queryParams = new URLSearchParams();
    if (uStr) {
      const u = JSON.parse(uStr);
      if (u.targetDomain) queryParams.append('domain', u.targetDomain);
      if (u.targetCompany) queryParams.append('company', u.targetCompany);
    }
    const qs = queryParams.toString() ? `?${queryParams.toString()}` : '';

    fetch(`http://localhost:8000/api/reports${qs}`)
      .then(r => r.json())
      .then(d => {
        if(d.status === 'success' && d.reports) {
           setReports(d.reports);
        }
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);
  return (
    <div className="space-y-10">
      <header className="flex flex-col md:flex-row md:items-end justify-between mb-12 gap-6">
        <div>
          <span className="text-[10px] font-mono tracking-[0.3em] text-primary-neon block mb-2">SYSTEM_MODULE: DOCUMENT_VAULT</span>
          <h1 className="text-4xl lg:text-5xl font-headline font-bold text-on-surface tracking-tight">Intelligence Reports</h1>
          <p className="text-slate-400 mt-4 max-w-xl text-sm leading-relaxed">Access and generate high-fidelity threat assessments, vulnerability audits, and network hygiene reports encrypted for level 4 clearance.</p>
        </div>
        <button className="bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest font-headline font-bold px-8 py-4 rounded-md shadow-[0_0_30px_rgba(0,255,136,0.2)] hover:scale-105 transition-transform flex items-center gap-2">
          <PlusCircle className="w-5 h-5" />
          Generate New Report
        </button>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
        <div className="md:col-span-2 glass-card p-8 rounded-xl relative overflow-hidden">
          <div className="relative z-10">
            <h3 className="text-primary-neon font-headline text-sm font-bold tracking-widest uppercase mb-6">Last Generated Assessment</h3>
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-2xl font-headline font-bold text-on-surface mb-2">Q3 Cyber Warfare Defense Audit</h2>
                <p className="text-slate-500 text-xs font-mono mb-6">UID: THREAT-882-ALPHA | DATE: 2023-10-24</p>
                <div className="flex gap-4">
                  <button className="bg-primary-neon/10 text-primary-neon border border-primary-neon/30 px-6 py-2 rounded-md text-xs font-bold uppercase tracking-widest hover:bg-primary-neon/20 transition-all">View Online</button>
                  <button className="flex items-center gap-2 text-on-surface/60 hover:text-primary-neon transition-colors text-xs font-bold uppercase tracking-widest">
                    <Download className="w-4 h-4" /> Download PDF
                  </button>
                </div>
              </div>
              <div className="hidden sm:block">
                <div className="h-24 w-24 rounded-full border-4 border-primary-neon/20 border-t-primary-neon flex items-center justify-center">
                  <span className="text-primary-neon font-headline font-bold text-xl">98%</span>
                </div>
                <p className="text-[10px] text-center mt-2 text-slate-500 tracking-widest uppercase">System Health</p>
              </div>
            </div>
          </div>
          <div className="absolute -right-20 -bottom-20 w-80 h-80 bg-primary-neon/5 rounded-full blur-3xl"></div>
        </div>

        <div className="glass-card p-8 rounded-xl flex flex-col justify-between">
          <h3 className="text-primary-neon font-headline text-sm font-bold tracking-widest uppercase">Storage Metrics</h3>
          <div className="space-y-4">
            <div className="flex justify-between items-end">
              <span className="text-2xl font-headline font-bold text-on-surface">1.2 GB</span>
              <span className="text-[10px] text-slate-500 font-mono">/ 5.0 GB</span>
            </div>
            <div className="w-full bg-surface-lowest h-1.5 rounded-full overflow-hidden">
              <div className="bg-primary-neon h-full w-[24%] shadow-[0_0_10px_#00ff88]"></div>
            </div>
            <p className="text-[10px] text-slate-400 font-mono">148 SECURE_DOCUMENTS RENDERED</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        {reports.map((report, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: i * 0.1 }}
            className="glass-card rounded-xl group hover:border-primary-neon/40 transition-all duration-500 flex flex-col overflow-hidden"
          >
            <div className="h-40 w-full relative bg-surface-lowest overflow-hidden">
              <img 
                src={report.image} 
                alt={report.title} 
                className="w-full h-full object-cover opacity-60 group-hover:opacity-80 transition-opacity"
                referrerPolicy="no-referrer"
              />
              <div className="absolute top-4 left-4 bg-surface-highest/80 backdrop-blur px-2 py-1 rounded text-[10px] font-mono text-primary-neon border border-primary-neon/20">
                {report.type}
              </div>
            </div>
            <div className="p-6">
              <h3 className="text-xl font-headline font-bold text-on-surface group-hover:text-primary-neon transition-colors mb-1">{report.title}</h3>
              <p className="text-slate-500 text-[11px] font-mono mb-6 uppercase tracking-wider">Generated: {report.date} • {report.size}</p>
              <div className="flex items-center justify-between mt-auto">
                <span className="text-[10px] text-slate-400 font-bold uppercase tracking-[0.1em]">{report.format}</span>
                <button className="bg-surface-highest p-2 rounded-lg text-primary-neon hover:bg-primary-neon hover:text-surface-lowest transition-all">
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </div>
          </motion.div>
        ))}
        
        <div className="bg-surface-lowest border-2 border-dashed border-primary-neon/20 rounded-xl flex flex-col items-center justify-center p-8 group hover:bg-surface-container transition-all cursor-pointer">
          <div className="h-16 w-16 rounded-full bg-primary-neon/5 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
            <PlusCircle className="w-8 h-8 text-primary-neon" />
          </div>
          <p className="text-on-surface font-headline font-bold text-lg mb-1">New Template</p>
          <p className="text-slate-500 text-xs text-center">Configure custom data nodes for automated reporting</p>
        </div>
      </div>

      <div className="mt-20 glass-card rounded-md py-2 overflow-hidden">
        <div className="flex whitespace-nowrap animate-marquee">
          <span className="text-[10px] font-mono tracking-widest text-primary-neon/60 px-4 uppercase">SYSTEM_LOG: REPORT_GEN_AUTO_CLEARED_ID_77</span>
          <span className="text-[10px] font-mono tracking-widest text-primary-neon px-4 uppercase">•</span>
          <span className="text-[10px] font-mono tracking-widest text-slate-500 px-4 uppercase">USER: OPERATOR_01 ACCESSED VAULT_LEVEL_4</span>
          <span className="text-[10px] font-mono tracking-widest text-primary-neon px-4 uppercase">•</span>
          <span className="text-[10px] font-mono tracking-widest text-primary-neon/60 px-4 uppercase">ENCRYPTION: AES-256-GCM_ACTIVE</span>
          <span className="text-[10px] font-mono tracking-widest text-primary-neon px-4 uppercase">•</span>
          <span className="text-[10px] font-mono tracking-widest text-slate-500 px-4 uppercase">LATENCY: 12ms</span>
        </div>
      </div>
    </div>
  );
}
