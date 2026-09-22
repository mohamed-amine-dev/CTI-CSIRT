$r = 'C:\Users\OUALLALI\Desktop\internship'
Write-Output '===== [1] the KPI .py files on disk (names only, real) ====='
Get-ChildItem (Join-Path $r 'app') -Recurse -Filter '*.py' |
  Where-Object { $_.Name -match 'darkweb|telegram|dark_web|tg_' } |
  ForEach-Object { '    ' + $_.Name }
Write-Output ''
Write-Output '===== [2] Dockerfile Stage-2 web_dist copy byte (the bake gate) ====='
$d = Get-Content (Join-Path $r 'Dockerfile')
$d | Where-Object { $_ -match 'COPY --from=frontend|WORKDIR /app|CMD \[' } | ForEach-Object { '    ' + $_ }
Write-Output ''
Write-Output '===== [3] KPI endpoint live (bytes the KPI cards read) ====='
docker exec cti-app python -c "import urllib.request,json; d=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/v1/feeds/darkweb/stats')); print(json.dumps(d,indent=1)[:600])" 2>&1 | ForEach-Object { '    ' + $_ }
Write-Output ''
Write-Output '===== [4] ClickHouse KPI truth independent of SPA ====='
docker exec cti-server clickhouse-client -q "SELECT table FROM system.tables WHERE database='cti'" 2>&1 | ForEach-Object { '    table: ' + $_ }