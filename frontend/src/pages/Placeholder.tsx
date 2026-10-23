import React from 'react';

export function Placeholder({ title }: { title: string }) {
  return (
    <div className="flex h-[80vh] flex-col items-center justify-center space-y-4">
      <div className="text-muted-foreground">
        <svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
        </svg>
      </div>
      <h1 className="text-2xl font-bold tracking-tight text-foreground">{title}</h1>
      <p className="text-muted-foreground max-w-md text-center">
        This section is currently under development. The backend API endpoints for this feature are not yet available.
      </p>
    </div>
  );
}
