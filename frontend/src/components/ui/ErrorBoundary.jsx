import React from 'react';
import { AlertTriangle } from 'lucide-react';

/**
 * ErrorBoundary — class-component guard that turns any render crash inside a
 * route into a real "something went wrong" state instead of a blank white/navy
 * screen. Wrap every page route with it (see App.jsx). Per-page data fetch
 * errors are handled by ErrorState; this catches anything else.
 */
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, message: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, message: error?.message || String(error) };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('Route error boundary caught:', error, info?.componentStack);
  }

  handleReset = () => {
    this.setState({ hasError: false, message: null });
    window.location.reload();
  };

  render() {
    if (!this.state.hasError) return this.props.children;
    return (
      <div className="flex flex-col items-center justify-center gap-4 rounded-xl border border-red-500/30 bg-red-500/5 px-6 py-16 text-center">
        <AlertTriangle size={30} className="text-red-400" aria-hidden="true" />
        <div>
          <p className="text-sm font-medium text-ink">Something went wrong</p>
          <p className="mt-1 max-w-md text-xs text-dim">
            This section hit an unexpected error{this.state.message ? `: ${this.state.message}` : ''}. The rest of the platform is unaffected.
          </p>
        </div>
        <button
          type="button"
          onClick={this.handleReset}
          className="focus-neon rounded-lg border border-line bg-raised px-3 py-2 text-xs font-semibold text-ink transition-colors hover:border-cyan-500/40"
        >
          Reload section
        </button>
      </div>
    );
  }
}
