param(
    [string]$ProjectPath = "C:\Users\VIDUSHI\Documents\edubild-social-agent"
)

Set-Location $ProjectPath
py -3 -m streamlit run frontend/dashboard.py --server.address 0.0.0.0 --server.port 8501
