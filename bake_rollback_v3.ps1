$ErrorActionPreference = 'Continue'
$r = 'C:\Users\OUALLALI\Desktop\internship'
Set-Location $r

Write-Output '===== [GATE] Stage-1 bake source NOW (reverting .dockerignore node_modules starve made the context valid) ====='
$ig = Get-Content (Join-Path $r '.dockerignore')
$hasLegacyNM  = [bool]($ig | Where-Object { $_ -match '^\s*frontend_legacy/node_modules/\s*$' })
$hasLegacyDist= [bool]($ig | Where-Object { $_ -match '^\s*frontend_legacy/dist/\s*$' })
Write-Output ('  .dockerignore now excludes: frontend_legacy/node_modules/ = {0} | frontend_legacy/dist/ = {1}' -f $hasLegacyNM,$hasLegacyDist)
Write-Output ''
Write-Output '===== [GATE] Dockerfile Stage-1 (byte-print before --build, as promised) ====='
$L = Get-Content (Join-Path $r 'Dockerfile')
for($i=14;$i -le 36;$i++){ if($i -le $L.Count){ Write-Output ("  {0,3}: {1}" -f $i,$L[$i-1]) } }
Write-Output ''
Write-Output '===== [COMPOSE CONFIG] syntax gate ====='
docker compose config --quiet
Write-Output ('  compose config rc: {0}' -f $LASTEXITCODE)
if ($LASTEXITCODE -ne 0) { Write-Output '  >>> STOP: compose config failed — nothing built. <<<'; exit 1 }

Write-Output ''
Write-Output '===== [BAKE] docker compose up --build -d (rollback: full 10-panel platform) ====='
docker compose up --build -d
Write-Output ('  up --build rc: {0}' -f $LASTEXITCODE)
if ($LASTEXITCODE -ne 0) { Write-Output '  >>> STOP: bake failed. Show me the build log above. <<<'; exit 1 }

Write-Output ''
Write-Output '===== [LIVE] wait for health, then probe the served platform ====='
for($i=1;$i -le 12;$i++){ Start-Sleep -Seconds 8; $s = docker ps --filter name=cti-app --format '{{.Status}}'; if($s -match 'healthy'){ break } }
Write-Output ('  cti-app status: {0}' -f $s)

foreach($m in @('Executive Overview','Threat Landscape','Threat Actors','Dark Web','Telegram','IoC Search','Data Explorer','Autonomous Triage','Alert Sheets','Live Threat Feeds')){
  $n = docker exec cti-app sh -lc ("grep -rl '{0}' /app/web/dist/assets/*.js 2>/dev/null | wc -l" -f $m)
  Write-Output ("     nav [{0}] present in served js: {1}" -f $m,$n.Trim())
}
Write-Output ''
Write-Output '===== [HTML] what :8000 serves right now ====='
docker exec cti-app sh -lc "wget -qO- http://127.0.0.1:8000/ 2>/dev/null | head -c 500"