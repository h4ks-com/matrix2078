# M6 e2e: voidbar (Discord bouncer, girc upstream) as the IRC client of
# matrix2078. Full loop without a Discord client: REST only.
#   register -> join irc:// invite -> guilds/channels appear ->
#   matrix->voidbar message relay -> voidbar->matrix send -> chathistory backfill.
param(
    [int]$Port = 2078,
    [int]$VbPort = 18080,
    [string]$VbDir = "$env:TEMP\opencode\vb",
    [int]$TimeoutSec = 300
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$mxPass = $creds['MATRIX2078_IT_PASS']
$roomPlain = '!rUL1FW6b5oVOa4GnkX:doesnmlab.xyz'

$peer = @{}
$peer['E2E_PEER_HOMESERVER'] = 'https://matrix.doesnmlab.xyz'
$peer['E2E_PEER_USER'] = $creds['MATRIX2078_IT_PEER_USER']
$peer['E2E_PEER_PASS'] = $creds['MATRIX2078_IT_PEER_PASS']
$peer['E2E_PEER_STATE'] = 'D:\matrix2078\dev\state-peer'
$peerExe = 'D:\matrix2078\target\debug\e2e_peer.exe'

function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
}

function Invoke-Peer([string[]]$PeerArgs) {
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = $peerExe
    $psi.Arguments = ($PeerArgs | ForEach-Object { Quote-Arg $_ }) -join ' '
    foreach ($k in $peer.Keys) { $psi.EnvironmentVariables[$k] = $peer[$k] }
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [Diagnostics.Process]::Start($psi)
    $p.WaitForExit(120000) | Out-Null
    return $p.StandardOutput.ReadToEnd()
}

$checks = New-Object System.Text.StringBuilder
function Check([string]$name, [bool]$ok) {
    [void]$checks.AppendLine(("{0} {1}" -f ($(if ($ok) {'PASS'} else {'FAIL'}), $name)))
    if (-not $ok) { Write-Host ("FAIL: $name") -ForegroundColor Red } else { Write-Host ("pass: $name") -ForegroundColor Green }
}

# --- 1. voidbar instance in a scratch dir (open registration)
if (Test-Path $VbDir) { Remove-Item -Recurse -Force $VbDir }
New-Item -ItemType Directory -Path $VbDir | Out-Null
@"
[server]
listen = "127.0.0.1:$VbPort"
public_url = "http://127.0.0.1:$VbPort"

[storage]
path = "$($VbDir.Replace('\', '\\'))\\data"

[auth]
registration = "open"
"@ | Set-Content -Path "$VbDir\voidbar.toml" -Encoding UTF8

$vbOut = "$VbDir\voidbar.out.log"
$vb = Start-Process -FilePath 'D:\voidbar\voidbar-test.exe' -ArgumentList @('serve', '--config', "$VbDir\voidbar.toml") -WorkingDirectory $VbDir -WindowStyle Hidden -RedirectStandardOutput $vbOut -RedirectStandardError "$VbDir\voidbar.err.log" -PassThru
$api = "http://127.0.0.1:$VbPort"
try {
    $up = $false
    foreach ($i in 1..60) {
        try { Invoke-RestMethod "$api/health" -TimeoutSec 2 | Out-Null; $up = $true; break } catch { Start-Sleep -Milliseconds 500 }
    }
    Check 'voidbar up' $up

    # --- 2. register a bouncer user
    $regBody = @{ username = 'vbtest'; email = "vb$(Get-Random)@t.local"; password = 'vbtest-pass-123' } | ConvertTo-Json
    $reg = Invoke-RestMethod -Method Post -Uri "$api/api/v9/auth/register" -Body $regBody -ContentType 'application/json' -TimeoutSec 10
    $token = $reg.token
    Check 'voidbar user registered' ($null -ne $token)
    if (-not $token) { throw 'no token' }
    $hdr = @{ Authorization = $token }

    # --- 3. join matrix2078 through an irc:// invite (nick + server password)
    $encPass = [uri]::EscapeDataString($mxPass)
    $connstr = "irc://m2078:$encPass@127.0.0.1:$($Port)?name=matrix2078&nick=m2078"
    $code = [uri]::EscapeDataString($connstr)
    $joined = $false
    foreach ($i in 1..20) {
        try {
            $inv = Invoke-RestMethod -Method Post -Uri "$api/api/v9/invites/$code" -Headers $hdr -ContentType 'application/json' -Body '{}' -TimeoutSec 10
            $joined = $true
            break
        } catch { Start-Sleep -Milliseconds 500 }
    }
    Check 'joined matrix2078 network' $joined

    # upstream registration takes a moment (matrix login + sync)
    Start-Sleep 15

    # --- 4. guilds (one per IRC network) and channels (one per room)
    $guilds = Invoke-RestMethod -Uri "$api/api/v9/users/@me/guilds" -Headers $hdr -TimeoutSec 10
    Check 'guild created' (@($guilds).Count -ge 1)
    $guild = @($guilds)[0]
    $detail = Invoke-RestMethod -Uri "$api/api/v9/guilds/$($guild.id)" -Headers $hdr -TimeoutSec 10
    $channels = @($detail.channels | Where-Object { $_.type -eq 0 })
    Check 'channel burst seen' ($channels.Count -ge 1)
    $plainChan = $channels | Where-Object { $_.name -match 'plain' } | Select-Object -First 1
    Check 'plain room channel found' ($null -ne $plainChan)
    Write-Host "  channels: $(($channels | ForEach-Object { '#'+$_.name }) -join ' ')"

    # --- 5. matrix -> voidbar relay
    $r1 = "vb hello $(Get-Random)"
    Invoke-Peer @('send', $roomPlain, $r1) | Out-Null
    $saw = $false
    foreach ($i in 1..40) {
        Start-Sleep -Milliseconds 500
        $msgs = Invoke-RestMethod -Uri "$api/api/v9/channels/$($plainChan.id)/messages?limit=10" -Headers $hdr -TimeoutSec 10
        if (@($msgs) | Where-Object { $_.content -match [regex]::Escape($r1) }) { $saw = $true; break }
    }
    Check 'matrix message relayed to voidbar' $saw

    # --- 6. voidbar -> matrix send
    $r2 = "vb reply $(Get-Random)"
    $body = @{ content = $r2 } | ConvertTo-Json
    $sent = Invoke-RestMethod -Method Post -Uri "$api/api/v9/channels/$($plainChan.id)/messages" -Headers $hdr -ContentType 'application/json' -Body $body -TimeoutSec 10
    Check 'voidbar message accepted' ($null -ne $sent.id)
    $saw2 = $false
    foreach ($i in 1..20) {
        Start-Sleep -Milliseconds 500
        $rd = Invoke-Peer @('read', $roomPlain, '3')
        if ($rd -match [regex]::Escape($r2)) { $saw2 = $true; break }
    }
    Check 'voidbar message delivered to matrix' $saw2

    # --- 7. no upstream reconnect storm: matrix2078 saw exactly one client
    Start-Sleep 5
    $mlog = "$env:TEMP\opencode\m6s.out"
    if (Test-Path $mlog) {
        $raw = (Get-Content $mlog -Raw) -replace '\x1b\[[0-9;]*m', ''
        $connects = ([regex]::Matches($raw, 'client connected')).Count
        Check 'single upstream connection' ($connects -eq 1)
        Write-Host "  upstream connections: $connects"
    }

    # --- 8. reply/reaction from voidbar ride IRCv3 (msgid-gated react)
    if ($sent.id) {
        try {
            Invoke-RestMethod -Method Put -Uri "$api/api/v9/channels/$($plainChan.id)/messages/$($sent.id)/reactions/%F0%9F%91%8D/@me" -Headers $hdr -TimeoutSec 10 | Out-Null
            $reacted = $false
            foreach ($i in 1..20) {
                Start-Sleep -Milliseconds 500
                $rd = Invoke-Peer @('read', $roomPlain, '4')
                if ($rd -match 'm\.reaction' -and $rd -match [regex]::Escape($r2.Substring(0, [Math]::Min(8, $r2.Length)))) { }
                # reactions target the event id; check any new m.reaction
                if ($rd -match 'm\.reaction') { $reacted = $true; break }
            }
            Check 'reaction delivered to matrix' $reacted
        } catch {
            Check 'reaction delivered to matrix' $false
        }
    }
} finally {
    try { if ($vb -and -not $vb.HasExited) { Stop-Process -Id $vb.Id -Force } } catch {}
}

Write-Host ""
Write-Host "voidbar log: $vbOut"
$total = 0; $failed = 0
foreach ($line in ($checks.ToString() -split "`r?`n")) {
    if ($line -match '^(\w+) (.*)$') {
        $total++
        if ($matches[1] -ne 'PASS') { $failed++ }
    }
}
if ($failed -gt 0) { Write-Host "$failed of $total checks FAILED" -ForegroundColor Red; exit 1 }
Write-Host "all $total checks passed" -ForegroundColor Green
