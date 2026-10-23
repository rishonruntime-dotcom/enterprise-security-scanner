import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AppLayout } from './components/layout/AppLayout';
import { Dashboard } from './pages/Dashboard';
import { Findings } from './pages/Findings';
import { Reports } from './pages/Reports';
import { Targets } from './pages/Targets';
import { ScanManagement } from './pages/ScanManagement';
import { Technologies } from './pages/Technologies';
import { RiskAnalytics } from './pages/RiskAnalytics';
import { Placeholder } from './pages/Placeholder';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 5000,
    },
  },
});

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<ScanManagement />} />
            <Route path="targets" element={<Targets />} />
            <Route path="findings" element={<Findings />} />
            <Route path="technologies" element={<Technologies />} />
            <Route path="risk" element={<RiskAnalytics />} />
            <Route path="reports" element={<Reports />} />
            <Route path="settings" element={<Placeholder title="Platform Settings" />} />
            <Route path="profile" element={<Placeholder title="User Profile" />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
