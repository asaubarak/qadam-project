import React from 'react';

// Provide a JSX-free implementation using React.createElement so this .ts file parses
export const createLazyComponent = <T extends React.ComponentType<any>>(
  importFunc: () => Promise<{ default: T }>,
  fallback?: React.ComponentType
) => {
  const LazyComponent = React.lazy(importFunc);

  return React.forwardRef<any, React.ComponentProps<T>>((props, ref) => {
    const fallbackEl = fallback
      ? React.createElement(fallback)
      : React.createElement(
          'div',
          { className: 'flex items-center justify-center p-8' },
          React.createElement('div', { className: 'animate-spin rounded-full h-8 w-8 border-b-2 border-primary' })
        );

    return React.createElement(
      React.Suspense,
      { fallback: fallbackEl },
      React.createElement(LazyComponent as any, Object.assign({}, props, { ref }))
    );
  });
};

// (Other utilities moved to performance.tsx - keep this file minimal to satisfy imports)
