$r = 'C:\Users\OUALLALI\Desktop\internship'
Write-Output '===== [1] TRUE served path now (the one that holds markers) ====='
docker exec cti-app sh -lc 'ls -la /app/web/dist 2>&1 | head -8'
Write-Output '  -- assets --'
docker exec cti-app sh -lc 'ls /app/web/dist/assets 2>&1 | head -5'
Write-Output ''
Write-Output '===== [2] full platform marker audit (correct path, real nav labels) ====='
$nav = @('Executive Overview','Threat Landscape','Threat Actors','Dark Web','Telegram','IoC Search','Data Explorer','Triage','Alert Sheets','Live Threat Feeds')
foreach ($m in $nav) {
  $n = docker exec cti-app sh -lc ("grep -rl '" + $m + "' /app/web/dist/assets/*.js 2>/dev/null | wc -l")
  Write-Output ("     [{0}] -> {1}" -f $m, $n.Trim())
}
Write-Output ''
Write-Output '===== [3] REAL ClickHouse tables (SHOW TABLES — no guessing names) ====='
docker exec cti-clickhouse clickhouse-client -q 'SHOW TABLES FROM cti' 2>&1 | ForEach-Object { '    ' + $_ }
Write-Output ''
Write-Output '===== [4] real row count per live table ====='
foreach ($t in @('darkweb','darkweb_items','telegram','telegram_items','threat_items','darkweb_raw')) {
  $n = docker exec cti-clickhouse clickhouse-client -q ("SELECT count() FROM cti." + $t) 2>&1
  Write-Output ("     cti.{0} = {1}" -f $t, $n.Trim())
}
Wait-Process -Id $PID; exit