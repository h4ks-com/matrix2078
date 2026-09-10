# M3 e2e: E2EE decryption, SAS verification over IRC (&matrix), encrypted media.
# Requires a running matrix2078 (rebuilt with M3) and dev/test-creds.env.
param(
    [int]$Port = 2078,
    [int]$TimeoutSec = 180,
    [string]$OutFile = "$env:TEMP\opencode\irc-m3.log"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$pass = $creds['MATRIX2078_IT_PASS']

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

$c = New-Object Net.Sockets.TcpClient('127.0.0.1', $Port)
$s = $c.GetStream()
$w = New-Object IO.StreamWriter($s)
$w.AutoFlush = $true
$w.NewLine = "`r`n"
$buf = New-Object byte[] 16384
$out = New-Object System.Text.StringBuilder
$checks = New-Object System.Text.StringBuilder

function Read-Available {
    while ($s.DataAvailable) {
        $n = $s.Read($buf, 0, 16384)
        if ($n -le 0) { break }
        [void]$out.Append([Text.Encoding]::UTF8.GetString($buf, 0, $n))
    }
}

function Wait-For([string]$pattern, [int]$secs) {
    $deadline = (Get-Date).AddSeconds($secs)
    while ((Get-Date) -lt $deadline) {
        Read-Available
        if ($out.ToString() -match $pattern) { return $true }
        Start-Sleep -Milliseconds 150
    }
    return $false
}

function Check([string]$name, [bool]$ok) {
    [void]$checks.AppendLine(("{0} {1}" -f ($(if ($ok) {'PASS'} else {'FAIL'}), $name)))
    if (-not $ok) { Write-Host ("FAIL: $name") -ForegroundColor Red } else { Write-Host ("pass: $name") -ForegroundColor Green }
}

# --- 1. register (plain PASS flow; caps for chathistory)
$w.WriteLine('CAP LS 302')
$w.WriteLine('CAP REQ :server-time message-tags batch draft/chathistory')
$w.WriteLine("PASS $pass")
$w.WriteLine('NICK m2078')
$w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
$w.WriteLine('CAP END')
Check 'welcome 001' (Wait-For ' 001 ' 30)
Check 'JOIN burst has enc room' (Wait-For '(?m)^:matrix2078 332 m2078 #\S+ :.*' 20)

# find the encrypted room's channel: its topic mentions the room id
# (RPL_TOPIC lines carry a server-time tag when negotiated, so anchor loosely)
$encChan = $null
foreach ($m in [regex]::Matches($out.ToString(), '(?m)332 m2078 (#\S+) :(.*)$')) {
    if ($m.Groups[2].Value -match '!XoWIBq2MspPOE2ltnk') { $encChan = $m.Groups[1].Value }
}
if (-not $encChan) {
    # fall back: any channel with 'enc' in the name
    foreach ($m in [regex]::Matches($out.ToString(), '(?m)332 m2078 (#\S+) :')) {
        if ($m.Groups[1].Value -match 'enc') { $encChan = $m.Groups[1].Value }
    }
}
Check 'found encrypted room channel' ($null -ne $encChan)
if ($null -eq $encChan) { $encChan = '#m2078-enc' }

# --- 2. E2EE live: peer sends (auto-encrypted) into the enc room
$stamp = "e2ee live relay $(Get-Random)"
$peerOut = Invoke-Peer @('send', '!XoWIBq2MspPOE2ltnk:doesnmlab.xyz', $stamp)
Check 'peer sent encrypted event' ($peerOut -match '(?m)^SENT \$')
Check 'e2ee message relayed decrypted' (Wait-For ("PRIVMSG {0} :{1}" -f [regex]::Escape($encChan), $stamp) 30)

# --- 3. E2EE chathistory
$w.WriteLine("CHATHISTORY LATEST $encChan * 20")
Check 'chathistory over encrypted room' (Wait-For ("(?s)BATCH \+\S+ chathistory {0}.*{1}" -f [regex]::Escape($encChan), $stamp) 20)

# --- 4. SAS verification over IRC: peer initiates
# reset the peer's devices first so the flow starts unverified (repeatable runs)
if (Test-Path 'D:\matrix2078\dev\state-peer') {
    $loginBody = @{ type = 'm.login.password'; identifier = @{ type = 'm.id.user'; user = $peer['E2E_PEER_USER'] }; password = $peer['E2E_PEER_PASS'] } | ConvertTo-Json -Depth 5 -Compress
    try {
        $tok = (Invoke-RestMethod -Method Post -Uri "$($peer['E2E_PEER_HOMESERVER'])/_matrix/client/v3/login" -Body $loginBody -ContentType 'application/json').access_token
        Invoke-RestMethod -Method Post -Uri "$($peer['E2E_PEER_HOMESERVER'])/_matrix/client/v3/logout/all?access_token=$tok" | Out-Null
    } catch { Write-Host "peer reset: $($_.Exception.Message)" }
    Remove-Item -Recurse -Force 'D:\matrix2078\dev\state-peer'
}

$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $peerExe
$psi.Arguments = (Quote-Arg 'request') + ' ' + (Quote-Arg '@m2078:doesnmlab.xyz')
foreach ($k in $peer.Keys) { $psi.EnvironmentVariables[$k] = $peer[$k] }
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$peerProc = [Diagnostics.Process]::Start($psi)
Check 'verification request surfaced' (Wait-For 'verification request from @m2078-peer' 30)

$w.WriteLine('PRIVMSG &matrix :verify')
Check 'verify list shows flow' (Wait-For '&matrix.*NOTICE m2078 :\[0\] @m2078-peer' 10)

$w.WriteLine('PRIVMSG &matrix :verify accept')
Check 'SAS emojis presented' (Wait-For 'SAS for @m2078-peer' 30)

$w.WriteLine('PRIVMSG &matrix :verify match')
Check 'verification done notice' (Wait-For 'verification with @m2078-peer\S* done' 30)
if (-not $peerProc.WaitForExit(30000)) { $peerProc.Kill() }
$peerLog = $peerProc.StandardOutput.ReadToEnd()
Check 'peer side verified' ($peerLog -match 'VERIFIED')

# --- 5. devices listing shows trust
$w.WriteLine('PRIVMSG &matrix :devices @m2078-peer:doesnmlab.xyz')
Check 'devices listing with trust' (Wait-For '(?s)&matrix.*NOTICE m2078 :devices of @m2078-peer.*trusted' 10)

# --- 6. encrypted media
$png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
[IO.File]::WriteAllBytes("$env:TEMP\opencode\m3-image.png", $png)
$peerOut = Invoke-Peer @('send-image', '!XoWIBq2MspPOE2ltnk:doesnmlab.xyz', "$env:TEMP\opencode\m3-image.png", 'e2e image')
Check 'peer sent encrypted image' ($peerOut -match '(?m)^SENT \$')
# match the LIVE relay by the event's msgid, not any historical [image] line
$imgMsgid = if ($peerOut -match '(?m)^SENT \$(\S+)') { $matches[1] } else { $null }
Check 'image line relayed' ($imgMsgid -and (Wait-For ("msgid={0}.*PRIVMSG [^ ]+ :\[image\] e2e image.*http" -f $imgMsgid) 45))

# fetch the local URL the client got (authenticated media cache, decrypted)
$url = $null
if ($imgMsgid -and $out.ToString() -match ("msgid={0}.*?\[image\] e2e image.*?(http://\S+)" -f $imgMsgid)) { $url = $matches[1] }
Check 'local media url present' ($null -ne $url)
if ($url) {
    $uri = [Uri]$url
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Host = $uri.Authority
    $resp = $req.GetResponse()
    $ms = New-Object IO.MemoryStream
    $resp.GetResponseStream().CopyTo($ms)
    $bytes = $ms.ToArray()
    $resp.Close()
    Check 'downloaded media is valid PNG' ($bytes.Length -ge 8 -and $bytes[0] -eq 0x89 -and $bytes[1] -eq 0x50)
    Check 'media content matches original' (([Convert]::ToBase64String($bytes)) -eq ([Convert]::ToBase64String($png)))
}

try { $w.WriteLine('QUIT :bye'); $c.Close() } catch {}
[IO.File]::WriteAllText($OutFile, $out.ToString())
''
$checks.ToString()
