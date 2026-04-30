param(
    [string]$ProjectPath = "C:\Users\VIDUSHI\Documents\edubild-social-agent"
)

Set-Location $ProjectPath
# Always use the project venv so google-genai, playwright-stealth, etc. are available
$VenvPython = Join-Path $ProjectPath "venv\Scripts\python.exe"
& $VenvPython -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
