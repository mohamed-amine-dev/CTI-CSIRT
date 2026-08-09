/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      // Semantic tokens resolved from CSS variables (see src/index.css).
      // Each theme (dark / light) defines the RGB triplets, so flipping the
      // `data-theme` attribute re-skins the whole app. `/<alpha-value>` lets
      // Tailwind generate opacity variants (bg-ink/80 etc.).
      colors: {
        base: 'rgb(var(--color-base) / <alpha-value>)',     // page background
        surface: 'rgb(var(--color-surface) / <alpha-value>)', // card surface
        raised: 'rgb(var(--color-raised) / <alpha-value>)',   // hover / raised
        line: 'rgb(var(--color-line) / <alpha-value>)',       // borders
        ink: 'rgb(var(--color-ink) / <alpha-value>)',         // primary text
        dim: 'rgb(var(--color-dim) / <alpha-value>)',         // secondary text
        faint: 'rgb(var(--color-faint) / <alpha-value>)',     // tertiary text
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      keyframes: {
        // Vertical ticker for the "recent high-priority feed" widget.
        ticker: {
          '0%': { transform: 'translateY(0)' },
          '100%': { transform: 'translateY(-50%)' },
        },
        // Live-status pulse.
        'pulse-glow': {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.3 },
        },
        // Card / modal entrance.
        'fade-in': {
          '0%': { opacity: 0, transform: 'translateY(6px)' },
          '100%': { opacity: 1, transform: 'translateY(0)' },
        },
      },
      animation: {
        ticker: 'ticker 30s linear infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'fade-in': 'fade-in 0.25s ease-out',
      },
    },
  },
  plugins: [],
};
