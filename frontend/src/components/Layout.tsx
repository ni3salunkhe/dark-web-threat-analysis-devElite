import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Shield, 
  AlertTriangle, 
  BarChart3, 
  Settings, 
  ListFilter, 
  Terminal as TerminalIcon,
  Bell,
  Search,
  ChevronRight
} from 'lucide-react';
import { cn } from '@/src/lib/utils';

const navItems = [
  { name: 'Dashboard', icon: LayoutDashboard, path: '/dashboard' },
  { name: 'Entities', icon: Shield, path: '/entities' },
  { name: 'Alerts', icon: AlertTriangle, path: '/alerts' },
  { name: 'Reports', icon: BarChart3, path: '/reports' },
  { name: 'Notify', icon: Bell, path: '/notify' },
  { name: 'Settings', icon: Settings, path: '/settings' },
];

export function Sidebar({ onOpenTerminal }: { onOpenTerminal?: () => void }) {
  const location = useLocation();

  return (
    <aside className="hidden lg:flex flex-col h-screen w-64 fixed left-0 top-0 bg-surface-lowest border-r border-surface-container pt-20 pb-12 z-40">
      <div className="px-6 mb-10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-surface-highest rounded-lg flex items-center justify-center border border-primary-neon/20">
            <Shield className="w-6 h-6 text-primary-neon fill-primary-neon/20" />
          </div>
          <div>
            <div className="font-headline text-xs font-bold tracking-[0.2em] text-primary-neon">OPERATOR_01</div>
            <div className="text-[10px] text-slate-500 tracking-widest">LEVEL_4_AUTH</div>
          </div>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3">
        {navItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.name}
              to={item.path}
              className={cn(
                "flex items-center gap-3 px-4 py-3 transition-all duration-300 rounded-lg group",
                isActive 
                  ? "bg-surface-container text-primary-neon border-r-4 border-primary-neon scale-105" 
                  : "text-slate-500 hover:bg-surface-container hover:text-primary-neon"
              )}
            >
              <item.icon className={cn("w-5 h-5", isActive && "fill-primary-neon/10")} />
              <span className="font-headline text-sm uppercase tracking-widest">{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="px-3 border-t border-surface-container pt-6 space-y-1">
        <button className="flex items-center gap-3 px-4 py-2 w-full text-slate-600 hover:text-primary-neon transition-colors">
          <ListFilter className="w-4 h-4" />
          <span className="text-[10px] uppercase tracking-widest font-headline">Logs</span>
        </button>
        <button 
          onClick={onOpenTerminal}
          className="flex items-center gap-3 px-4 py-2 w-full text-slate-600 hover:text-primary-neon transition-colors"
        >
          <TerminalIcon className="w-4 h-4" />
          <span className="text-[10px] uppercase tracking-widest font-headline">Terminal</span>
        </button>
      </div>
    </aside>
  );
}

export function Topbar({ onOpenTerminal }: { onOpenTerminal?: () => void }) {
  return (
    <header className="flex justify-between items-center w-full px-6 py-3 bg-surface-low fixed top-0 z-[100] shadow-[0_0_20px_rgba(0,255,136,0.05)] border-b border-surface-container">
      <div className="flex items-center gap-12">
        <div className="text-xl font-bold tracking-tighter text-primary-neon uppercase font-headline">BREACHSIGHT</div>
        <nav className="hidden md:flex items-center gap-8 font-headline tracking-tight">
          {navItems.map((item) => (
            <Link 
              key={item.name} 
              to={item.path} 
              className="text-slate-400 hover:text-primary-neon transition-colors text-sm uppercase tracking-widest"
            >
              {item.name}
            </Link>
          ))}
        </nav>
      </div>

      <div className="flex items-center gap-4">
        <div className="relative hidden lg:block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 w-4 h-4" />
          <input 
            className="bg-surface-lowest border-none rounded-md pl-10 pr-4 py-1.5 text-xs font-sans text-on-surface focus:ring-1 focus:ring-primary-neon w-64 shadow-[inset_0_2px_4px_rgba(0,0,0,0.5)]" 
            placeholder="SEARCH_SYSTEM..." 
            type="text"
          />
        </div>
        <button className="p-2 text-slate-400 hover:bg-surface-bright/50 rounded transition-all relative">
          <Bell className="w-5 h-5" />
          <span className="absolute top-2 right-2 w-2 h-2 bg-primary-neon rounded-full"></span>
        </button>
        <button onClick={onOpenTerminal} className="p-2 text-slate-400 hover:bg-surface-bright/50 rounded transition-all">
          <TerminalIcon className="w-5 h-5" />
        </button>
        <div className="w-8 h-8 rounded-lg overflow-hidden border border-primary-neon/30">
          <img 
            alt="Operator Profile" 
            className="h-full w-full object-cover"
            src="https://picsum.photos/seed/operator/100/100"
            referrerPolicy="no-referrer"
          />
        </div>
      </div>
    </header>
  );
}

export function Footer() {
  return (
    <footer className="hidden md:flex fixed bottom-0 w-full justify-between px-6 py-2 border-t border-surface-container z-50 bg-surface-lowest font-headline text-[10px] tracking-[0.2em] uppercase">
      <div className="text-slate-600 flex items-center gap-4">
        <span className="text-primary-neon font-mono">SYSTEM_STATUS: OPTIMAL | V2.4.0-STABLE</span>
        <div className="flex items-center gap-1">
          <div className="w-1.5 h-1.5 bg-primary-neon rounded-full animate-pulse"></div>
          <span className="text-slate-500">ENCRYPTED_LINK_ESTABLISHED</span>
        </div>
      </div>
      <div className="flex gap-6">
        <a className="text-slate-600 hover:text-primary-neon opacity-80 hover:opacity-100 transition-all" href="#">Privacy Protocol</a>
        <a className="text-slate-600 hover:text-primary-neon opacity-80 hover:opacity-100 transition-all" href="#">Node Status</a>
        <a className="text-slate-600 hover:text-primary-neon opacity-80 hover:opacity-100 transition-all" href="#">Encryption Keys</a>
      </div>
    </footer>
  );
}

export function Ticker() {
  return (
    <div className="w-full bg-surface-lowest border border-outline-variant rounded-md py-1.5 px-4 mb-10 overflow-hidden">
      <div className="flex gap-12 whitespace-nowrap animate-marquee items-center">
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-primary-neon">NODE_CONNECTED: LON-EDGE-012</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-slate-500">TRAFFIC_LOAD: 42%</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-error-neon">CRITICAL_VULN_DETECTED: ENTITY_ID_884</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-slate-500">ENCRYPTION: AES-256-GCM</span>
        {/* Duplicate for seamless loop */}
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-primary-neon">NODE_CONNECTED: LON-EDGE-012</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-slate-500">TRAFFIC_LOAD: 42%</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-error-neon">CRITICAL_VULN_DETECTED: ENTITY_ID_884</span>
        <span className="text-[10px] tracking-[0.2em] uppercase font-headline text-slate-500">ENCRYPTION: AES-256-GCM</span>
      </div>
    </div>
  );
}

export function MobileBottomNav() {
  const location = useLocation();
  return (
    <nav className="lg:hidden fixed bottom-6 left-4 right-4 z-[90] bg-surface-lowest/90 backdrop-blur-md border border-surface-container rounded-2xl flex justify-around p-2 shadow-2xl">
      {navItems.map((item) => {
        const isActive = location.pathname === item.path;
        return (
          <Link 
            key={item.name} 
            to={item.path} 
            className={cn(
              "p-2 rounded-xl flex flex-col items-center gap-1 transition-colors", 
              isActive ? "text-primary-neon bg-primary-neon/10" : "text-slate-500 hover:text-slate-300"
            )}
          >
            <item.icon className="w-5 h-5" />
            <span className="text-[8px] font-headline uppercase tracking-widest">{item.name}</span>
          </Link>
        )
      })}
    </nav>
  )
}
