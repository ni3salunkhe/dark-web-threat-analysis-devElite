import React, { useState, useEffect, useRef } from 'react';
import { Terminal, X, Minimize2, Maximize2 } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function TerminalOverlay({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) {
  const [logs, setLogs] = useState<any[]>([]);
  const [isMinimized, setIsMinimized] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    
    // Connect to SSE for logs
    const es = new EventSource('http://localhost:8000/api/logs/stream');
    
    es.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        setLogs(prev => {
          const newLogs = [...prev, payload];
          // Keep only last 150 to prevent DOM bloat
          if (newLogs.length > 150) return newLogs.slice(newLogs.length - 150);
          return newLogs;
        });
      } catch(e) {}
    };

    return () => {
      es.close();
    };
  }, [isOpen]);

  useEffect(() => {
    if (endRef.current && !isMinimized) {
      endRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, isMinimized]);

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0, y: 100 }}
          animate={{ 
            opacity: 1, 
            y: 0,
            height: isMinimized ? '48px' : '400px'
          }}
          exit={{ opacity: 0, y: 100 }}
          transition={{ type: "spring", damping: 25, stiffness: 200 }}
          className="fixed bottom-0 right-4 lg:right-12 w-full max-w-2xl bg-surface-lowest border border-primary-neon/30 rounded-t-xl shadow-[0_0_40px_rgba(0,0,0,0.8)] overflow-hidden z-[9999] flex flex-col font-mono"
        >
          {/* Header */}
          <div className="flex justify-between items-center bg-surface-highest/80 px-4 py-2 border-b border-primary-neon/20 cursor-pointer" onClick={() => setIsMinimized(!isMinimized)}>
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-primary-neon" />
              <span className="text-xs text-primary-neon font-bold tracking-widest uppercase">BreachSight Core_Terminal</span>
              <span className="ml-4 text-[10px] text-slate-500 animate-pulse">STREAMING LIVE DB/CRAWLER VERBOSE...</span>
            </div>
            
            <div className="flex items-center gap-3">
              <button 
                onClick={(e) => { e.stopPropagation(); setIsMinimized(!isMinimized); }}
                className="text-slate-400 hover:text-white transition-colors"
              >
                {isMinimized ? <Maximize2 className="w-3.5 h-3.5" /> : <Minimize2 className="w-3.5 h-3.5" />}
              </button>
              <button 
                onClick={(e) => { e.stopPropagation(); onClose(); }}
                className="text-slate-400 hover:text-red-400 transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Body */}
          {!isMinimized && (
            <div className="p-4 flex-1 overflow-y-auto bg-black/50 backdrop-blur text-[11px] md:text-xs leading-relaxed custom-scrollbar">
              {logs.length === 0 ? (
                <div className="text-slate-500 italic">Waiting for incoming log stream...</div>
              ) : (
                <div className="flex flex-col gap-1">
                  {logs.map((log, i) => (
                    <div key={i} className="flex gap-3 hover:bg-white/5 px-1 rounded transition-colors break-words">
                      <span className="text-slate-500 shrink-0">[{log.time}]</span>
                      <span className={cn(
                        "font-bold shrink-0 w-12",
                        log.level === 'ERROR' ? 'text-red-400' :
                        log.level === 'WARNING' ? 'text-yellow-400' :
                        log.level === 'INFO' ? 'text-blue-400' : 'text-slate-300'
                      )}>
                        {log.level}
                      </span>
                      <span className={cn(
                        "flex-1",
                        log.msg.includes('Fail') || log.msg.includes('Error') ? 'text-red-300' :
                        log.msg.includes('Success') || log.msg.includes('collected') ? 'text-primary-neon' :
                        'text-slate-300'
                      )}>
                        {log.msg}
                      </span>
                    </div>
                  ))}
                  <div ref={endRef} />
                </div>
              )}
            </div>
          )}
        </motion.div>
      )}
    </AnimatePresence>
  );
}
