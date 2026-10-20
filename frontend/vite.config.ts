import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { apiBaseUrlGuard } from './scripts/validate-api-base-url.mjs'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Only VITE_* variables are read here: they are the ones Vite inlines into the
  // public browser bundle. `loadEnv` merges the resolved .env files with any
  // real environment variables (process.env wins), which is exactly the value
  // Vite substitutes for `import.meta.env.VITE_API_BASE_URL`.
  const env = loadEnv(mode, process.cwd(), 'VITE_')

  return {
    plugins: [
      react(),
      tailwindcss(),
      apiBaseUrlGuard({ value: env.VITE_API_BASE_URL, env: process.env })
    ],
    server: {
      host: true,
      port: 5173
    }
  }
})
