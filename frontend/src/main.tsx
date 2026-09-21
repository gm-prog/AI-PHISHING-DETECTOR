import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

import { AuthProvider } from './context/AuthContext'
import { PhishingProvider } from './context/PhishingContext'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <PhishingProvider>
        <App />
      </PhishingProvider>
    </AuthProvider>
  </StrictMode>,
)
