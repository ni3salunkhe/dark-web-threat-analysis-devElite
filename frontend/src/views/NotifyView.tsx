import React, { useState, useEffect } from 'react';
import { 
  BellRing, 
  PlusCircle, 
  Globe2, 
  Mail, 
  Building2, 
  ToggleRight, 
  ToggleLeft,
  Search,
  Activity,
  Trash2
} from 'lucide-react';
import { motion } from 'motion/react';
import { cn } from '@/src/lib/utils';
import { Ticker } from '@/src/components/Layout';

export function NotifyView() {
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  
  // New target modal state
  const [isAdding, setIsAdding] = useState(false);
  const [newEntityValue, setNewEntityValue] = useState('');
  const [newEntityType, setNewEntityType] = useState('DOMAIN');
  
  const userStr = localStorage.getItem('dwtis_user');
  const user = userStr ? JSON.parse(userStr) : null;

  const fetchTargets = () => {
    if(!user) return;
    fetch(`http://localhost:8000/api/targets?user_id=${user.id}`)
      .then(r => r.json())
      .then(d => {
        if(d.status === 'success') {
          setTargets(d.targets);
        }
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchTargets();
  }, []);

  const handleToggle = async (targetId: number, currentStatus: number) => {
    try {
      await fetch('http://localhost:8000/api/targets/toggle', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targetId, isEnabled: currentStatus === 1 ? 0 : 1 })
      });
      fetchTargets();
    } catch(e) {
      console.error(e);
    }
  };

  const handleAddTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if(!newEntityValue || !user) return;
    
    try {
      await fetch('http://localhost:8000/api/targets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            userId: user.id, 
            entityValue: newEntityValue, 
            entityType: newEntityType 
        })
      });
      setNewEntityValue('');
      setIsAdding(false);
      fetchTargets();
    } catch(e) {
      console.error(e);
    }
  };

  return (
    <div className="space-y-8">
      <Ticker />

      <header className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-8">
        <div>
          <div className="text-[10px] tracking-[0.3em] uppercase text-primary-neon mb-2 font-headline">Crawler Engine</div>
          <h1 className="text-4xl md:text-5xl font-headline font-bold tracking-tight text-on-surface">NOTIFY_TARGETS</h1>
          <p className="mt-3 text-sm text-slate-400 max-w-xl">
            Configure entities for continuous background ingestion. Active targets will aggressively poll threat databases and stream immediate events to your SSE feed.
          </p>
        </div>
        <button 
            onClick={() => setIsAdding(!isAdding)}
            className="bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest px-6 py-3 rounded-md font-headline font-bold text-sm tracking-tight flex items-center gap-2 transition-transform hover:scale-105 active:scale-95 shadow-[0_0_20px_rgba(0,255,136,0.2)]"
        >
          <PlusCircle className="w-4 h-4" />
          {isAdding ? 'CANCEL' : 'ADD NEW TARGET'}
        </button>
      </header>

      {isAdding && (
        <motion.form 
            initial={{ opacity: 0, y: -10 }} 
            animate={{ opacity: 1, y: 0 }} 
            onSubmit={handleAddTarget}
            className="glass-panel p-6 rounded-xl border border-primary-neon/30 flex flex-col md:flex-row gap-4 items-end"
        >
          <div className="flex-1 space-y-2">
            <label className="text-[10px] text-primary-neon uppercase tracking-widest font-headline">Target Value (Domain, Email, etc)</label>
            <input 
              required
              value={newEntityValue}
              onChange={(e) => setNewEntityValue(e.target.value)}
              className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all font-mono" 
              placeholder="e.g. securebank.com" 
            />
          </div>
          <div className="w-full md:w-48 space-y-2">
            <label className="text-[10px] text-primary-neon uppercase tracking-widest font-headline">Entity Type</label>
            <select 
                value={newEntityType}
                onChange={(e) => setNewEntityType(e.target.value)}
                className="w-full bg-surface-lowest text-on-surface border-none rounded-lg p-3 font-mono text-sm uppercase tracking-widest appearance-none focus:ring-1 focus:ring-primary-neon"
            >
              <option value="DOMAIN">Domain</option>
              <option value="EMAIL">Email</option>
              <option value="COMPANY">Company</option>
            </select>
          </div>
          <button type="submit" className="bg-surface-lowest border border-outline-variant hover:border-primary-neon hover:text-primary-neon transition-colors h-12 px-8 rounded-lg text-sm font-bold uppercase tracking-widest font-headline w-full md:w-auto">
            DEPLOY
          </button>
        </motion.form>
      )}

      <div className="glass-card rounded-xl border border-outline-variant overflow-hidden">
        <div className="p-4 bg-surface-container border-b border-outline-variant flex items-center gap-3">
          <Activity className="w-5 h-5 text-primary-neon animate-pulse" />
          <h3 className="font-headline font-bold text-sm tracking-widest uppercase text-on-surface">Active Scanning Queue</h3>
        </div>
        
        {loading ? (
            <div className="p-12 text-center text-slate-500 font-mono text-xs animate-pulse">Syncing pipeline...</div>
        ) : targets.length === 0 ? (
            <div className="p-12 text-center flex flex-col items-center">
                <BellRing className="w-12 h-12 text-slate-600 mb-4" />
                <p className="text-slate-400 font-mono text-sm max-w-sm">No targets configured. Your background crawler is currently dormant.</p>
            </div>
        ) : (
            <div className="divide-y divide-outline-variant">
              {targets.map((tgt: any) => (
                  <div key={tgt.id} className={cn(
                      "p-6 flex items-center justify-between transition-colors",
                      tgt.is_enabled ? "bg-primary-neon/5" : "bg-transparent opacity-60 grayscale"
                  )}>
                      <div className="flex items-center gap-4">
                          <div className={cn(
                              "w-12 h-12 rounded-lg flex items-center justify-center border",
                              tgt.is_enabled ? "bg-surface-lowest border-primary-neon/30 text-primary-neon" : "bg-surface-highest border-outline-variant text-slate-500"
                          )}>
                              {tgt.entity_type === 'DOMAIN' ? <Globe2 className="w-6 h-6" /> : 
                               tgt.entity_type === 'EMAIL' ? <Mail className="w-6 h-6" /> : <Building2 className="w-6 h-6" />}
                          </div>
                          <div>
                              <div className="text-lg font-mono font-bold text-on-surface">{tgt.entity_value}</div>
                              <div className="flex items-center gap-2 mt-1">
                                  <span className="text-[10px] uppercase tracking-widest font-headline bg-surface-highest px-2 py-0.5 rounded text-slate-400">
                                      {tgt.entity_type}
                                  </span>
                                  {tgt.last_scan && (
                                      <span className="text-[9px] font-mono text-slate-500">
                                          LAST SWEEP: {tgt.last_scan}
                                      </span>
                                  )}
                              </div>
                          </div>
                      </div>
                      
                      <div className="flex items-center gap-6">
                          <div className="hidden sm:block text-right mr-4">
                              <span className={cn(
                                  "text-[10px] font-headline uppercase tracking-widest block",
                                  tgt.is_enabled ? "text-primary-neon animate-pulse" : "text-slate-500"
                              )}>
                                  {tgt.is_enabled ? 'Scanning Active' : 'Off-line'}
                              </span>
                          </div>
                          <button 
                              onClick={() => handleToggle(tgt.id, tgt.is_enabled)}
                              className="transition-transform hover:scale-110 active:scale-90"
                          >
                              {tgt.is_enabled ? (
                                  <ToggleRight className="w-10 h-10 text-primary-neon" />
                              ) : (
                                  <ToggleLeft className="w-10 h-10 text-slate-600 delay-75" />
                              )}
                          </button>
                      </div>
                  </div>
              ))}
            </div>
        )}
      </div>
    </div>
  );
}
