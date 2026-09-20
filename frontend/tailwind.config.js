import tailwindcssAnimate from 'tailwindcss-animate';

/** @type {import('tailwindcss').Config} */
export default {
  darkMode: ['class'],
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      // -------------------------------------------------------------------
      // Semantic tokens resolved from CSS variables (see src/index.css).
      // Each theme (dark / light) defines the RGB triplets, so flipping the
      // `data-theme` attribute re-skins the whole app. `/<alpha-value>` lets
      // Tailwind generate opacity variants (bg-ink/80 etc.).
      // -------------------------------------------------------------------
      colors: {
        base: 'rgb(var(--color-base) / <alpha-value>)',     // page background
        surface: 'rgb(var(--color-surface) / <alpha-value>)', // card surface
        raised: 'rgb(var(--color-raised) / <alpha-value>)',   // hover / raised
        line: 'rgb(var(--color-line) / <alpha-value>)',       // borders
        ink: 'rgb(var(--color-ink) / <alpha-value>)',         // primary text
        dim: 'rgb(var(--color-dim) / <alpha-value>)',         // secondary text
        faint: 'rgb(var(--color-faint) / <alpha-value>)',     // tertiary text

        // ---- shadcn/ui tokens (HSL vars, see index.css) ----
        border: 'hsl(var(--border))',
        input: 'hsl(var(--input))',
        ring: 'hsl(var(--ring))',
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        primary: {
          DEFAULT: 'hsl(var(--primary))',
          foreground: 'hsl(var(--primary-foreground))',
        },
        secondary: {
          DEFAULT: 'hsl(var(--secondary))',
          foreground: 'hsl(var(--secondary-foreground))',
        },
        destructive: {
          DEFAULT: 'hsl(var(--destructive))',
          foreground: 'hsl(var(--destructive-foreground))',
        },
        muted: {
          DEFAULT: 'hsl(var(--muted))',
          foreground: 'hsl(var(--muted-foreground))',
        },
        accent: {
          DEFAULT: 'hsl(var(--accent))',
          foreground: 'hsl(var(--accent-foreground))',
        },
        popover: {
          DEFAULT: 'hsl(var(--popover))',
          foreground: 'hsl(var(--popover-foreground))',
        },
        card: {
          DEFAULT: 'hsl(var(--card))',
          foreground: 'hsl(var(--card-foreground))',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      borderRadius: {
        lg: 'var(--radius)',
        md: 'calc(var(--radius) - 2px)',
        sm: 'calc(var(--radius) - 4px)',
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
        // shadcn/ui shadcn animations (accordion, dialogs, overlay).
        'accordion-down': {
          from: { height: '0' },
          to: { height: 'var(--radix-accordion-content-height)' },
        },
        'accordion-up': {
          from: { height: 'var(--radix-accordion-content-height)' },
          to: { height: '0' },
        },
      },
      animation: {
        ticker: 'ticker 30s linear infinite',
        'pulse-glow': 'pulse-glow 2s ease-in-out infinite',
        'fade-in': 'fade-in 0.25s ease-out',
        'accordion-down': 'accordion-down 0.2s ease-out',
        'accordion-up': 'accordion-up 0.2s ease-out',
      },
    },
  },
  plugins: [tailwindcssAnimate],
};