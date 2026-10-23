import React from 'react';
import { NavLink } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  FileText, 
  Target, 
  Cpu,
  BarChart3,
  Settings,
  User,
  LogOut,
  Play
} from 'lucide-react';

const navItems = [
  { name: 'Dashboard', path: '/', icon: LayoutDashboard },
  { name: 'Scans', path: '/scans', icon: Play },
  { name: 'Findings', path: '/findings', icon: ShieldAlert },
  { name: 'Reports', path: '/reports', icon: FileText },
  { name: 'Targets', path: '/targets', icon: Target },
  { name: 'Technologies', path: '/technologies', icon: Cpu },
  { name: 'Risk Analytics', path: '/risk', icon: BarChart3 },
];

export function Sidebar() {
  return (
    <div className="flex h-full w-64 flex-col bg-card border-r border-border">
      <div className="flex h-16 items-center px-6 border-b border-border">
        <ShieldAlert className="h-6 w-6 text-primary mr-2" />
        <span className="text-lg font-bold">Enterprise Scanner</span>
      </div>
      
      <div className="flex-1 overflow-y-auto py-4">
        <nav className="space-y-1 px-3">
          {navItems.map((item) => (
            <NavLink
              key={item.name}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-secondary text-secondary-foreground'
                    : 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground'
                }`
              }
            >
              <item.icon className="mr-3 h-5 w-5 flex-shrink-0" aria-hidden="true" />
              {item.name}
            </NavLink>
          ))}
        </nav>
      </div>
      
      <div className="border-t border-border p-4">
        <div className="space-y-1">
          <NavLink
            to="/settings"
            className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-secondary/50 hover:text-foreground transition-colors"
          >
            <Settings className="mr-3 h-5 w-5 flex-shrink-0" />
            Settings
          </NavLink>
          <NavLink
            to="/profile"
            className="flex items-center rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-secondary/50 hover:text-foreground transition-colors"
          >
            <User className="mr-3 h-5 w-5 flex-shrink-0" />
            Profile
          </NavLink>
          <button
            className="flex w-full items-center rounded-md px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-secondary/50 hover:text-destructive transition-colors"
          >
            <LogOut className="mr-3 h-5 w-5 flex-shrink-0" />
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
}
