#!/usr/bin/env pwsh
# start.ps1 — Starts both the backend (FastAPI) and frontend (Vite) servers
# Run this from the project root: .\start.ps1

$ProjectRoot = $PSScriptRoot

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║      SENTINEL AI — Phishing Detector              ║" -ForegroundColor Cyan
Write-Host "║      Starting Development Servers...              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# --- Start Backend ---
Write-Host "[1/2] Starting FastAPI Backend on http://localhost:8000 ..." -ForegroundColor Yellow
$BackendDir = Join-Path $ProjectRoot "backend"
$BackendProcess = Start-Process -FilePath "powershell.exe" `
  -ArgumentList "-NoExit", "-Command", `
    "cd '$BackendDir'; Write-Host 'Backend: Activating venv...' -ForegroundColor Cyan; .\venv\Scripts\activate; Write-Host 'Backend: Starting uvicorn...' -ForegroundColor Green; uvicorn app.main:app --reload --host 127.0.0.1 --port 8000" `
  -PassThru

Start-Sleep -Seconds 2

# --- Start Frontend ---
Write-Host "[2/2] Starting Vite Frontend on http://localhost:5173 ..." -ForegroundColor Yellow
$FrontendDir = Join-Path $ProjectRoot "frontend"
$FrontendProcess = Start-Process -FilePath "powershell.exe" `
  -ArgumentList "-NoExit", "-Command", `
    "cd '$FrontendDir'; Write-Host 'Frontend: Starting Vite dev server...' -ForegroundColor Green; npm run dev" `
  -PassThru

Write-Host ""
Write-Host "✅ Both servers launched in separate windows!" -ForegroundColor Green
Write-Host ""
Write-Host "   Backend API:   http://localhost:8000" -ForegroundColor Cyan
Write-Host "   Frontend App:  http://localhost:5173" -ForegroundColor Cyan
Write-Host "   API Docs:      http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host ""
Write-Host "Close the separate terminal windows to stop the servers." -ForegroundColor DarkGray
Write-Host ""
