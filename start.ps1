# PhishGuard - Dev Server Startup Script
# Usage: .\start.ps1
# Set your API keys here (or export them from your system environment)

# ── Load from .env if present ───────────────────────────────────────────────
if (Test-Path "$PSScriptRoot\.env") {
    Get-Content "$PSScriptRoot\.env" | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith("#") -and $line -match '^([^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $val = $matches[2].Trim().Trim('"').Trim("'")
            if ($val) {
                [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
            }
        }
    }
}

# ── Required: OpenRouter & Groq API Keys ─────────────────────────────────────────────
if (-not $env:OPENROUTER_API_KEY) { $env:OPENROUTER_API_KEY = "your_openrouter_key_here" }
if (-not $env:GROQ_API_KEY) { $env:GROQ_API_KEY = "your_groq_key_here" }

# ── Start the server ─────────────────────────────────────────────────────────
Write-Host "Starting PhishGuard..." -ForegroundColor Cyan
Write-Host "OPENROUTER_API_KEY set: $($env:OPENROUTER_API_KEY -ne $null -and $env:OPENROUTER_API_KEY -ne '' -and $env:OPENROUTER_API_KEY -ne 'your_openrouter_key_here')" -ForegroundColor Gray
Write-Host "GROQ_API_KEY       set: $($env:GROQ_API_KEY -ne $null -and $env:GROQ_API_KEY -ne '' -and $env:GROQ_API_KEY -ne 'your_groq_key_here')" -ForegroundColor Gray
Write-Host ""

$env:PYTHONIOENCODING = "utf-8"

# SEC-09: Use waitress production server when available.
# The app.py __main__ block handles server selection automatically:
#   - Non-debug mode: uses waitress (production WSGI server)
#   - Debug mode:     uses Flask dev server with threaded=True
.\.venv\Scripts\python.exe app.py
