import React, { useState } from 'react';
import { Shield, Eye, EyeOff, Github, Terminal as TerminalIcon, ChevronRight } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';

export function LoginView() {
  const [showPassword, setShowPassword] = React.useState(false);
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch('http://localhost:8000/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Login failed');
      }
      
      // Store operator context for multitenant routing
      localStorage.setItem('dwtis_user', JSON.stringify(data.user));
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden">
      <div className="fixed inset-0 terminal-grid opacity-30 pointer-events-none"></div>
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-md w-full glass-panel rounded-xl p-8 shadow-2xl relative overflow-hidden"
      >
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary-neon/40 to-transparent"></div>
        
        <div className="flex flex-col items-center mb-10">
          <div className="w-14 h-14 bg-surface-highest rounded-lg flex items-center justify-center mb-4 border border-outline-variant">
            <Shield className="w-8 h-8 text-primary-neon fill-primary-neon/20" />
          </div>
          <h1 className="font-headline text-2xl font-bold tracking-tighter text-primary-neon">BREACHSIGHT</h1>
          <div className="mt-8 text-center">
            <h2 className="font-headline text-3xl text-on-surface mb-2">Welcome back</h2>
            <p className="text-on-surface-variant text-sm font-light">Enter your credentials to access the terminal.</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-error-container/20 border border-error-neon/30 text-error-neon text-xs rounded text-center">
            {error}
          </div>
        )}

        <form className="space-y-6" onSubmit={handleLogin}>
          <div className="space-y-2">
            <label className="font-sans text-[10px] uppercase tracking-[0.1em] text-on-surface-variant ml-1">Email Address</label>
            <input 
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full recessed-input py-3 px-4 text-on-surface placeholder:text-on-surface/20 focus:ring-1 focus:ring-primary-neon transition-all" 
              placeholder="operator@breachsight.io" 
              type="email"
            />
          </div>

          <div className="space-y-2">
            <div className="flex justify-between items-end ml-1">
              <label className="font-sans text-[10px] uppercase tracking-[0.1em] text-on-surface-variant">Password</label>
              <a className="font-sans text-[10px] uppercase tracking-[0.1em] text-primary-neon hover:underline" href="#">Forgot?</a>
            </div>
            <div className="relative">
              <input 
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full recessed-input py-3 px-4 text-on-surface placeholder:text-on-surface/20 focus:ring-1 focus:ring-primary-neon transition-all" 
                placeholder="••••••••••••" 
                type={showPassword ? "text" : "password"}
              />
              <button 
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 -translate-y-1/2 text-on-surface-variant hover:text-on-surface transition-colors"
              >
                {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
              </button>
            </div>
          </div>

          <button 
            type="submit"
            disabled={loading}
            className="block w-full bg-gradient-to-br from-primary-soft to-primary-neon text-surface-lowest font-headline font-bold py-3.5 rounded-lg text-center transition-all neon-glow hover:scale-[1.01] active:scale-[0.98] disabled:opacity-50"
          >
            {loading ? 'Authenticating...' : 'Continue'}
          </button>
        </form>

        <div className="relative my-8">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-outline-variant"></div>
          </div>
          <div className="relative flex justify-center text-[10px] uppercase tracking-[0.2em] font-sans">
            <span className="px-4 bg-[#1A2027] text-on-surface-variant">OR AUTHORIZE WITH</span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <button className="flex items-center justify-center gap-2 py-3 bg-surface-lowest border border-outline-variant rounded-lg hover:bg-surface-bright transition-colors">
            <img src="https://www.google.com/favicon.ico" className="w-4 h-4 grayscale opacity-70" alt="Google" />
            <span className="font-sans text-xs uppercase tracking-wider text-on-surface">Google</span>
          </button>
          <button className="flex items-center justify-center gap-2 py-3 bg-surface-lowest border border-outline-variant rounded-lg hover:bg-surface-bright transition-colors">
            <TerminalIcon className="w-4 h-4 text-on-surface-variant" />
            <span className="font-sans text-xs uppercase tracking-wider text-on-surface">GitHub</span>
          </button>
        </div>

        <div className="mt-10 pt-6 border-t border-outline-variant flex flex-col items-center gap-4">
          <Link to="/register" className="text-on-surface-variant hover:text-primary-neon transition-colors font-sans text-xs tracking-wider flex items-center gap-2">
            No account? Get started <ChevronRight className="w-4 h-4" />
          </Link>
          
          <div className="flex justify-between w-full mt-2">
            <div className="flex flex-col">
              <span className="font-sans text-[8px] uppercase tracking-widest text-on-surface-variant opacity-40">System Node</span>
              <span className="font-sans text-[10px] text-primary-neon/70 tracking-widest">BREACH-NY-04</span>
            </div>
            <div className="flex flex-col items-end">
              <span className="font-sans text-[8px] uppercase tracking-widest text-on-surface-variant opacity-40">Status</span>
              <span className="font-sans text-[10px] text-secondary-neon tracking-widest flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-secondary-neon animate-pulse"></span>
                ENCRYPTED
              </span>
            </div>
          </div>
        </div>
      </motion.div>

      <footer className="mt-auto py-4 font-sans text-[10px] uppercase tracking-widest text-on-surface/40">
        © 2024 BREACHSIGHT TERMINAL v4.0.2
      </footer>
    </div>
  );
}

export function RegisterView() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    fullName: '',
    email: '',
    password: '',
    confirm: '',
    targetDomain: '',
    targetCompany: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (formData.password !== formData.confirm) {
      setError('Passwords do not match');
      return;
    }
    
    setLoading(true);
    try {
      const res = await fetch('http://localhost:8000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          fullName: formData.fullName,
          email: formData.email,
          password: formData.password,
          targetDomain: formData.targetDomain,
          targetCompany: formData.targetCompany
        })
      });
      
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || data.message || 'Registration failed');
      }
      
      // On success, redirect directly to dashboard
      navigate('/dashboard');
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-6 relative overflow-hidden">
      <div className="fixed inset-0 terminal-grid opacity-30 pointer-events-none"></div>
      
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="max-w-md w-full glass-panel rounded-xl p-8 shadow-2xl relative overflow-hidden"
      >
        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-primary-neon/40 to-transparent"></div>
        
        <div className="flex flex-col items-center mb-6">
          <div className="w-14 h-14 bg-surface-highest rounded-lg flex items-center justify-center mb-4 border border-outline-variant">
            <Shield className="w-8 h-8 text-primary-neon fill-primary-neon/20" />
          </div>
          <h1 className="font-headline text-2xl font-bold tracking-tighter text-primary-neon">BREACHSIGHT</h1>
          <div className="mt-8 text-center">
            <h2 className="font-headline text-3xl text-on-surface mb-2">Create Account</h2>
            <p className="text-on-surface-variant text-sm font-light">Register operators and set Intelligence Targets</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-error-container/20 border border-error-neon/30 text-error-neon text-xs rounded text-center">
            {error}
          </div>
        )}

        <form className="space-y-4" onSubmit={handleSubmit}>
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Full Name</label>
            <input 
              required
              value={formData.fullName}
              onChange={e => setFormData({...formData, fullName: e.target.value})}
              className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
              placeholder="Operator Name" 
              type="text" 
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Email Address</label>
            <input 
              required
              value={formData.email}
              onChange={e => setFormData({...formData, email: e.target.value})}
              className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
              placeholder="operator@breachsight.sh" 
              type="email" 
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Target Domain</label>
              <input 
                value={formData.targetDomain}
                onChange={e => setFormData({...formData, targetDomain: e.target.value})}
                className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
                placeholder="example.com" 
                type="text" 
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Target Company</label>
              <input 
                value={formData.targetCompany}
                onChange={e => setFormData({...formData, targetCompany: e.target.value})}
                className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
                placeholder="Acme Corp" 
                type="text" 
              />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Password</label>
              <input 
                required
                value={formData.password}
                onChange={e => setFormData({...formData, password: e.target.value})}
                className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
                placeholder="••••••••" 
                type="password" 
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] uppercase tracking-widest font-bold text-primary-neon ml-1">Confirm</label>
              <input 
                required
                value={formData.confirm}
                onChange={e => setFormData({...formData, confirm: e.target.value})}
                className="w-full recessed-input py-3 px-4 text-on-surface focus:ring-1 focus:ring-primary-neon transition-all" 
                placeholder="••••••••" 
                type="password" 
              />
            </div>
          </div>
          <button 
            type="submit"
            disabled={loading}
            className="w-full bg-primary-neon text-surface-lowest font-headline font-bold py-3.5 rounded-lg text-center neon-glow hover:opacity-90 transition-all active:scale-[0.98] mt-4 disabled:opacity-50"
          >
            {loading ? 'Initializing...' : 'Create Account'}
          </button>
        </form>

        <div className="relative my-8 text-center">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-outline-variant"></div>
          </div>
          <span className="relative bg-[#1a2027] px-4 text-[10px] uppercase tracking-[0.2em] font-bold text-on-surface-variant/60">OR SIGN UP WITH</span>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <button className="flex items-center justify-center gap-2 py-2.5 bg-surface-container border border-outline-variant rounded-lg text-on-surface text-sm font-medium hover:bg-surface-bright transition-colors">
            <img src="https://www.google.com/favicon.ico" className="w-4 h-4 grayscale opacity-70" alt="Google" />
            Google
          </button>
          <button className="flex items-center justify-center gap-2 py-2.5 bg-surface-container border border-outline-variant rounded-lg text-on-surface text-sm font-medium hover:bg-surface-bright transition-colors">
            <TerminalIcon className="w-4 h-4" />
            GitHub
          </button>
        </div>

        <div className="mt-8 flex justify-between items-center text-[9px] uppercase tracking-widest font-mono text-on-surface-variant/40 border-t border-outline-variant pt-4">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-primary-neon animate-pulse"></span>
            SYSTEM_NODE: EN-SEC-04
          </div>
          <div className="flex items-center gap-2">
            <Shield className="w-3 h-3 fill-current" />
            ENCRYPTED_AUTH_V4
          </div>
        </div>
      </motion.div>

      <div className="mt-6 text-center">
        <p className="text-sm text-on-surface-variant/70">
          Already have an account? 
          <Link to="/" className="text-primary-neon font-semibold hover:underline ml-1">Sign in</Link>
        </p>
      </div>
    </div>
  );
}
