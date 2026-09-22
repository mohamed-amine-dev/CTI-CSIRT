import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite build for the Argus CTI dashboard.
//
//  * In development, `/api` and `/health` are proxied to the FastAPI backend on
//    port 8000, so the SPA runs with zero CORS configuration.
//  * The production build is emitted to `../web/dist` — the exact directory the
//    FastAPI app mounts and serves (`WEB_DIR` in app/main.py). One `npm run
//    build` therefore produces a deployable, same-origin SPA.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/health': 'http://127.0.0.1:8000',
    },
  },
  build: {
    outDir: '../web/dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        // Split the heavy vendors so the app shell stays small and cacheable.
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          charts: ['recharts'],
          icons: ['lucide-react'],
        },
      },
    },
  },
});
