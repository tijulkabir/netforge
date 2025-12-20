import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/netforge/',
  server: {
    host: true, // Listen on all local IPs (192.168.x.x)
    port: 5173, // Default port, but strictPort: false will let it find the next available one if busy
    strictPort: false,
  }
})
