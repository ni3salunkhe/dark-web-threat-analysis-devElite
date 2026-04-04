import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Outlet } from 'react-router-dom';
import { Sidebar, Topbar, Footer, MobileBottomNav } from './components/Layout';
import { LandingView } from './views/LandingView';
import { LoginView, RegisterView } from './views/AuthViews';
import { DashboardView } from './views/DashboardView';
import { EntitiesView } from './views/EntitiesView';
import { AlertsView } from './views/AlertsView';
import { ReportsView } from './views/ReportsView';
import { NotifyView } from './views/NotifyView';
import { SettingsView } from './views/SettingsView';

function AppLayout() {
  return (
    <div className="min-h-screen bg-background">
      <Topbar />
      <Sidebar />
      <main className="lg:ml-64 pt-24 pb-28 md:pb-20 px-6 lg:px-12 max-w-7xl mx-auto overflow-x-hidden">
        <Outlet />
      </main>
      <Footer />
      <MobileBottomNav />
    </div>
  );
}

export default function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingView />} />
        <Route path="/login" element={<LoginView />} />
        <Route path="/register" element={<RegisterView />} />
        
        <Route element={<AppLayout />}>
          <Route path="/dashboard" element={<DashboardView />} />
          <Route path="/entities" element={<EntitiesView />} />
          <Route path="/alerts" element={<AlertsView />} />
          <Route path="/reports" element={<ReportsView />} />
          <Route path="/notify" element={<NotifyView />} />
          <Route path="/settings" element={<SettingsView />} />
        </Route>

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}
