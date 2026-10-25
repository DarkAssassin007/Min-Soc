import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard talks to the Mini SOC backend. In development Vite proxies
// /api and /ws to the backend so the browser sees a single origin (which also
// keeps the strict Content-Security-Policy from the backend valid).
const backend = process.env.VITE_BACKEND || 'http://127.0.0.1:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: false,
    proxy: {
      '/api': { target: backend, changeOrigin: true },
      '/ws': { target: backend.replace(/^http/, 'ws'), ws: true },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 1200,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    css: false,
  },
})
