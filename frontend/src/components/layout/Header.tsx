import React from 'react';
import { Bell, Search, Activity } from 'lucide-react';
import { useQuery } from '@tanstack/react-query';
import api from '../../lib/api';

export function Header() {
  const { data: health } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await api.get('/health');
      return res.data;
    },
    refetchInterval: 30000,
  });

  const isHealthy = health?.status === 'ok';

  return (
    <header className="flex h-16 items-center justify-between border-b border-border bg-card px-6">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-96">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search targets, findings..."
            className="w-full rounded-md border border-input bg-background pl-9 pr-4 py-2 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
          />
        </div>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm text-muted-foreground bg-secondary/50 px-3 py-1.5 rounded-full">
          <Activity className={`h-4 w-4 ${isHealthy ? 'text-green-500' : 'text-destructive'}`} />
          <span>API: {isHealthy ? 'Connected' : 'Disconnected'}</span>
        </div>
        
        <button className="relative rounded-full p-2 text-muted-foreground hover:bg-secondary transition-colors">
          <Bell className="h-5 w-5" />
          <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-destructive"></span>
        </button>
      </div>
    </header>
  );
}
