import React, { useState } from 'react';
import { 
  Shield, 
  ChevronRight, 
  AlertCircle,
  CheckCircle2,
  Globe,
  Mail,
  ExternalLink,
  Github,
  Twitter,
  ArrowRight
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'motion/react';
import { cn } from '@/src/lib/utils';

export function LandingView() {
  const [searchQuery, setSearchQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searchResponse, setSearchResponse] = useState<any>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery) return;
    setIsSearching(true);
    setSearchResponse(null);
    try {
      const res = await fetch(`http://localhost:8000/api/public_search?query=${encodeURIComponent(searchQuery)}`);
      const data = await res.json();
      // Artificial delay for the 'Scanner' effect
      setTimeout(() => { 
         setSearchResponse(data);
         setIsSearching(false);
      }, 1500);
    } catch(err) {
      console.error(err);
      setIsSearching(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0E141A] text-on-surface selection:bg-primary-neon selection:text-surface-lowest overflow-x-hidden">
      {/* Background Geometric Lines - Large Hexagonal Pattern */}
      <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden opacity-20">
        <svg className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[140%] h-[140%] text-primary-neon/10" viewBox="0 0 100 100">
          <path d="M50 0 L100 25 L100 75 L50 100 L0 75 L0 25 Z" fill="none" stroke="currentColor" strokeWidth="0.05" />
          <path d="M50 10 L90 30 L90 70 L50 90 L10 70 L10 30 Z" fill="none" stroke="currentColor" strokeWidth="0.03" />
          <path d="M50 20 L80 35 L80 65 L50 80 L20 65 L20 35 Z" fill="none" stroke="currentColor" strokeWidth="0.02" />
          <line x1="50" y1="0" x2="50" y2="100" stroke="currentColor" strokeWidth="0.01" />
          <line x1="0" y1="25" x2="100" y2="75" stroke="currentColor" strokeWidth="0.01" />
          <line x1="0" y1="75" x2="100" y2="25" stroke="currentColor" strokeWidth="0.01" />
        </svg>
      </div>

      {/* Navigation */}
      <nav className="fixed top-8 left-1/2 -translate-x-1/2 w-[calc(100%-4rem)] max-w-6xl z-50">
        <div className="bg-[#151C24]/60 backdrop-blur-xl border border-white/5 rounded-2xl px-10 h-20 flex items-center justify-between shadow-2xl">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-primary-neon rounded-lg flex items-center justify-center shadow-[0_0_20px_rgba(0,255,136,0.3)]">
              <Shield className="text-[#0E141A] w-6 h-6" />
            </div>
            <span className="font-headline text-2xl font-bold tracking-tighter">BreachSight</span>
          </div>
          
          <div className="hidden lg:flex items-center gap-10 text-[11px] font-headline font-bold tracking-[0.2em] uppercase text-slate-400">
            <a href="#" className="hover:text-primary-neon transition-colors">Breaches</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Passwords</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Monitoring</a>
            <a href="#" className="hover:text-primary-neon transition-colors">API</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Resources</a>
          </div>

          <div className="flex items-center gap-8">
            <Link to="/login" className="text-[11px] font-headline font-bold tracking-[0.2em] uppercase text-slate-400 hover:text-on-surface transition-colors">Sign In</Link>
            <Link to="/register" className="bg-primary-neon text-[#0E141A] px-6 py-3 rounded-xl text-[11px] font-headline font-bold tracking-[0.2em] uppercase hover:shadow-[0_0_30px_rgba(0,255,136,0.4)] transition-all">
              Get Started
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative pt-64 pb-40 px-8">
        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-20 items-center">
          <div className="relative z-10 w-full max-w-lg">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="inline-flex items-center gap-3 px-4 py-2 rounded-full bg-primary-neon/5 border border-primary-neon/20 text-primary-neon text-[10px] font-headline font-bold tracking-[0.3em] uppercase mb-10"
            >
              <span className="w-2 h-2 rounded-full bg-primary-neon animate-pulse shadow-[0_0_10px_#00FF88]"></span>
              Live Network Monitoring Active
            </motion.div>
            
            <motion.h1 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="font-headline text-7xl md:text-9xl font-bold tracking-tighter text-on-surface mb-10 leading-[0.85]"
            >
              Shield Your <br />
              <span className="text-primary-neon">Digital Identity</span>
            </motion.h1>
            
            <motion.p 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
              className="text-slate-400 text-xl md:text-2xl max-w-xl mb-14 leading-relaxed font-light"
            >
              Enterprise-grade breach intelligence for individuals. Monitor thousands of underground forums and data dumps in real-time.
            </motion.p>

            <motion.form 
              onSubmit={handleSearch}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="relative w-full"
            >
              <div className="flex items-center bg-[#151C24] border border-white/5 p-2 rounded-2xl w-full shadow-3xl focus-within:border-primary-neon/30 transition-all relative z-10">
                <input 
                  type="text" 
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Enter email or domain to scan..." 
                  className="bg-transparent border-none focus:ring-0 text-base px-6 flex-1 text-on-surface placeholder:text-slate-600 font-medium"
                />
                <button type="submit" disabled={isSearching} className="bg-primary-neon text-[#0E141A] px-8 py-4 rounded-xl font-headline font-bold text-sm uppercase tracking-widest flex items-center gap-3 hover:shadow-[0_0_30px_rgba(0,255,136,0.4)] disabled:opacity-50 transition-all">
                  {isSearching ? 'SCANNING...' : 'Analyze Exposure'} {!isSearching && <ChevronRight className="w-5 h-5" />}
                </button>
              </div>

              {/* Fake laser scan line effect while searching */}
              {isSearching && (
                  <motion.div 
                      initial={{ top: 0, opacity: 0 }}
                      animate={{ top: '100%', opacity: [0, 1, 1, 0] }}
                      transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
                      className="absolute left-0 w-full h-[2px] bg-primary-neon shadow-[0_0_15px_#00FF88] z-20 pointer-events-none"
                  />
              )}

              {/* Public Search Results Dropdown */}
              <AnimatePresence>
                {searchResponse && (
                  <motion.div
                    initial={{ opacity: 0, y: -20, height: 0 }}
                    animate={{ opacity: 1, y: 0, height: 'auto' }}
                    exit={{ opacity: 0, y: -20, height: 0 }}
                    className="mt-4 bg-[#151C24]/90 backdrop-blur-xl border border-primary-neon/20 rounded-xl overflow-hidden shadow-2xl"
                  >
                    <div className="p-5 border-b border-white/5 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                             {searchResponse.findings_count > 0 ? (
                                 <AlertCircle className="w-5 h-5 text-error-neon animate-pulse" />
                             ) : (
                                 <CheckCircle2 className="w-5 h-5 text-primary-neon" />
                             )}
                             <span className="font-headline font-bold text-sm tracking-widest uppercase">
                                 {searchResponse.findings_count > 0 ? `${searchResponse.findings_count} Exposures Detected` : 'No Immediate Exposures Found'}
                             </span>
                        </div>
                    </div>
                    
                    {searchResponse.findings_count > 0 ? (
                        <div className="p-5 space-y-4">
                            {searchResponse.findings.map((finding: any, idx: number) => (
                                <div key={idx} className="flex justify-between items-center p-3 rounded-lg bg-white/5">
                                    <div>
                                        <div className="text-sm font-bold text-error-neon blur-[1px] select-none hover:blur-none transition-all">{finding.source}</div>
                                        <div className="text-[10px] text-slate-400 font-mono mt-1 blur-[1px] select-none">Date: {finding.date}</div>
                                    </div>
                                    <div className="text-right">
                                        <div className="text-xs text-on-surface mb-1 blur-[1px] select-none">{finding.exposed_types.join(', ')}</div>
                                        <div className="text-[9px] uppercase tracking-widest text-error-neon">{finding.severity} Risk</div>
                                    </div>
                                </div>
                            ))}
                            <div className="pt-4 mt-2 border-t border-white/5 text-center">
                                <Link to="/register" className="text-xs font-bold text-primary-neon hover:underline truncate uppercase tracking-widest">
                                    Create a free account to unblur and secure your data <ArrowRight className="w-3 h-3 inline ml-1" />
                                </Link>
                            </div>
                        </div>
                    ) : (
                        <div className="p-6 text-center">
                            <p className="text-sm text-slate-400 mb-4">You are clear in our rapid index. However, deep-web monitoring requires continuous authenticated querying.</p>
                            <Link to="/register" className="inline-block bg-primary-neon/10 text-primary-neon px-6 py-2 rounded uppercase font-headline tracking-widest text-xs font-bold hover:bg-primary-neon/20 transition-colors">
                                Start Deep Continuous Scan
                            </Link>
                        </div>
                    )}
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.form>
          </div>

          {/* Hero Visual */}
          <div className="relative flex items-center justify-center">
            {/* Central Shield Graphic */}
            <motion.div 
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.4, duration: 0.8 }}
              className="relative z-10 w-80 h-80 bg-[#151C24] border border-white/5 rounded-[3rem] flex items-center justify-center shadow-[0_0_150px_rgba(0,255,136,0.05)]"
            >
              <div className="absolute inset-0 bg-gradient-to-br from-primary-neon/10 to-transparent rounded-[3rem]"></div>
              <div className="w-48 h-48 bg-primary-neon/5 rounded-[2rem] flex items-center justify-center border border-primary-neon/10">
                <Shield className="w-24 h-24 text-primary-neon relative z-10 drop-shadow-[0_0_30px_rgba(0,255,136,0.6)]" />
              </div>
            </motion.div>

            {/* Floating Status Cards */}
            <motion.div 
              initial={{ opacity: 0, y: 20, x: 20 }}
              animate={{ opacity: 1, y: 0, x: 0 }}
              transition={{ delay: 0.6 }}
              className="absolute -top-6 -right-6 md:-right-16 z-20 bg-[#151C24]/95 backdrop-blur-2xl border border-white/10 p-5 rounded-2xl flex items-center gap-5 shadow-4xl"
            >
              <div className="w-12 h-12 bg-error-neon/10 rounded-xl flex items-center justify-center">
                <AlertCircle className="w-6 h-6 text-error-neon" />
              </div>
              <div>
                <div className="text-[10px] font-bold tracking-[0.2em] text-error-neon uppercase mb-0.5">Threat Detected</div>
                <div className="text-sm text-on-surface font-mono font-bold">IP: 192.168.1.104</div>
              </div>
            </motion.div>

            <motion.div 
              initial={{ opacity: 0, y: -20, x: -20 }}
              animate={{ opacity: 1, y: 0, x: 0 }}
              transition={{ delay: 0.7 }}
              className="absolute -bottom-10 -left-6 md:-left-16 z-20 bg-[#151C24]/95 backdrop-blur-2xl border border-white/10 p-5 rounded-2xl flex items-center gap-5 shadow-4xl"
            >
              <div className="w-12 h-12 bg-primary-neon/10 rounded-xl flex items-center justify-center">
                <CheckCircle2 className="w-6 h-6 text-primary-neon" />
              </div>
              <div>
                <div className="text-[10px] font-bold tracking-[0.2em] text-primary-neon uppercase mb-0.5">Security Scan</div>
                <div className="text-sm text-on-surface font-mono font-bold">Status: Operational</div>
              </div>
            </motion.div>

            {/* Geometric Background Lines for Visual */}
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
              <div className="w-[140%] h-[140%] border border-primary-neon/5 rounded-full animate-[spin_60s_linear_infinite]"></div>
              <div className="w-[120%] h-[120%] border border-primary-neon/5 rounded-[4rem] rotate-45 animate-[spin_45s_linear_infinite_reverse]"></div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="py-32 border-t border-white/5 bg-[#0A0F14]">
        <div className="max-w-7xl mx-auto px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-16">
            <div className="text-center md:text-left group">
              <div className="font-headline text-6xl font-bold text-on-surface mb-3 tracking-tighter group-hover:text-primary-neon transition-colors">14.2B</div>
              <div className="text-[11px] font-headline font-bold tracking-[0.4em] text-slate-500 uppercase">Breached Records</div>
            </div>
            <div className="text-center md:text-left group">
              <div className="font-headline text-6xl font-bold text-primary-neon mb-3 tracking-tighter">2.4M</div>
              <div className="text-[11px] font-headline font-bold tracking-[0.4em] text-slate-500 uppercase">Threats Neutralized</div>
            </div>
            <div className="text-center md:text-left group">
              <div className="font-headline text-6xl font-bold text-on-surface mb-3 tracking-tighter group-hover:text-primary-neon transition-colors">0.02s</div>
              <div className="text-[11px] font-headline font-bold tracking-[0.4em] text-slate-500 uppercase">API Latency</div>
            </div>
            <div className="text-center md:text-left group">
              <div className="font-headline text-6xl font-bold text-primary-neon mb-3 tracking-tighter">99.9%</div>
              <div className="text-[11px] font-headline font-bold tracking-[0.4em] text-slate-500 uppercase">Uptime Reliability</div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-20 px-8 border-t border-white/5 bg-[#0E141A]">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-16">
          <div className="flex flex-col md:flex-row items-center gap-10">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 bg-primary-neon/10 rounded-xl flex items-center justify-center">
                <Shield className="text-primary-neon w-6 h-6" />
              </div>
              <span className="font-headline text-2xl font-bold tracking-tighter">BreachSight</span>
            </div>
            <div className="h-4 w-px bg-white/10 hidden md:block"></div>
            <span className="text-[12px] text-slate-600 font-medium tracking-wide">© 2024 Terminal Security Corp.</span>
          </div>
          
          <div className="flex flex-wrap justify-center gap-12 text-[11px] font-headline font-bold tracking-[0.2em] uppercase text-slate-500">
            <a href="#" className="hover:text-primary-neon transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Status</a>
            <a href="#" className="hover:text-primary-neon transition-colors">Support</a>
          </div>

          <div className="flex items-center gap-6">
            <button className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center text-slate-400 hover:text-primary-neon hover:bg-primary-neon/10 transition-all">
              <Twitter className="w-5 h-5" />
            </button>
            <button className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center text-slate-400 hover:text-primary-neon hover:bg-primary-neon/10 transition-all">
              <Github className="w-5 h-5" />
            </button>
            <button className="w-12 h-12 bg-white/5 rounded-full flex items-center justify-center text-slate-400 hover:text-primary-neon hover:bg-primary-neon/10 transition-all">
              <Globe className="w-5 h-5" />
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
