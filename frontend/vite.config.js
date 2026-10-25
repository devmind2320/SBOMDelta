import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  server: {
    port: 5173,
    // The Go API sets permissive CORS headers, but proxying in development
    // keeps the frontend talking to a same-origin /api path, which is how it
    // will be deployed behind one host in production.
    proxy: {
      '/api': {
        // 127.0.0.1, not localhost: localhost may resolve to IPv4 or IPv6, and a
        // different process on one of them would answer instead of the API.
        target: process.env.VITE_API_TARGET ?? 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
})
