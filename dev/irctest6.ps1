# M5 e2e: DM/query mapping both ways, invite accept/decline.
# Requires a running matrix2078 (rebuilt with M5) and dev/test-creds.env.
param(
    [int]$Port = 2078,
    [int]$TimeoutSec = 240,
    [string]$OutFile = "$env:TEMP\opencode\irc-m5.log"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$pass = $creds['MATRIX2078_IT_PASS']
$mxid = '@m2078:doesnmlab.xyz'

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
$w = New-Object IO.StreamWriter($s, (New-Object System.Text.UTF8Encoding($false)))
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

# --- 1. register
$w.WriteLine('CAP LS 302')
$w.WriteLine('CAP REQ :server-time message-tags batch echo-message')
$w.WriteLine("PASS $pass")
$w.WriteLine('NICK m2078')
$w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
$w.WriteLine('CAP END')
Check 'welcome 001' (Wait-For ' 001 ' 30)
Check 'JOIN burst (old rooms stay channels)' (Wait-For '(?m)^(@time=[^ ]+ )?:matrix2078 332 m2078 #m2078-plain :.*' 20)

# --- 2. DM: ensure the DM room is joined, then query both ways
$r1 = Get-Random
$peerOut = Invoke-Peer @('dm', $mxid, "dm hello $r1")
Check 'peer dm sent' ($peerOut -match '(?m)^SENT \$')
$dmRoom = if ($peerOut -match '(?m)^SENT \$\S+ (\S+)') { $matches[1] } else { $null }
Check 'dm room id captured' ($null -ne $dmRoom)

# if we are not in the DM room yet there is an invite prompt naming it
$invN = $null
$promptPat = 'invite #(\d+): [^\r\n]*\[' + [regex]::Escape($dmRoom) + '\]'
if (Wait-For $promptPat 15) {
    $all = [regex]::Matches($out.ToString(), $promptPat)
    $invN = $all[$all.Count - 1].Groups[1].Value
    $w.WriteLine("PRIVMSG &matrix :accept $invN")
    Check 'dm accepted as query' (Wait-For 'NOTICE m2078 :joined DM with m2078-peer' 30)
} else {
    Check 'dm already established' ($true)
}

# message flows as a query PRIVMSG addressed to our nick
$r2 = Get-Random
Invoke-Peer @('dm', $mxid, "dm hello $r2") | Out-Null
Check 'dm relayed as query PRIVMSG' (Wait-For (':m2078-peer![^ ]+ PRIVMSG m2078 :.*' + [regex]::Escape("dm hello $r2")) 45)
# no JOIN for the query (it is not a channel)
Check 'no channel JOIN for DM' (-not ($out.ToString() -match ':m2078-peer![^ ]+ JOIN #'))

# IRC -> Matrix over the query (send to all deduped query names; one of them
# is the room the peer is in — multiple DM rooms per pair are legal Matrix)
$r3 = "dm reply $(Get-Random)"
foreach ($qn in @('m2078-peer', 'm2078-peer_2', 'm2078-peer_3')) {
    $w.WriteLine("PRIVMSG $qn :$r3")
    Start-Sleep -Milliseconds 300
}
Check 'dm query echo' (Wait-For ([regex]::Escape($r3)) 20)
Start-Sleep 4
$rd = Invoke-Peer @('read', $dmRoom, '4')
Check 'matrix saw dm reply' ($rd -match [regex]::Escape($r3))

# --- 3. channel invite: prompt -> accept -> JOIN burst -> relay
$r4 = Get-Random
$invName = "m5inv$r4"
$peerOut = Invoke-Peer @('mkinvite', $invName, $mxid)
Check 'peer created invite room' ($peerOut -match '(?m)^CREATED ')
$invRoom = if ($peerOut -match '(?m)^CREATED (\S+) ') { $matches[1] } else { $null }
Check 'invite room id captured' ($null -ne $invRoom)
Check 'channel invite prompted' (Wait-For ('NOTICE m2078 :invite #\d+: ' + [regex]::Escape($invName)) 30)
$invN2 = $null
if ($out.ToString() -match ('(?s).*invite #(\d+): ' + [regex]::Escape($invName))) { $invN2 = $matches[1] }
Check 'channel invite index parsed' ($null -ne $invN2)
if ($invN2) {
    $w.WriteLine("PRIVMSG &matrix :accept $invN2")
    Check 'channel accepted' (Wait-For 'NOTICE m2078 :joined #m5inv' 30)
    $chan = if ($out.ToString() -match 'NOTICE m2078 :joined (#[a-z0-9_\-]+)') { $matches[1] } else { '#?' }
    Check 'accept emitted JOIN burst' (Wait-For (':m2078![^ ]+ JOIN ' + [regex]::Escape($chan)) 10)
}
$r5 = "post-accept $(Get-Random)"
Invoke-Peer @('send', $invRoom, $r5) | Out-Null
Check 'post-accept message relayed' (Wait-For (':m2078-peer![^ ]+ PRIVMSG #m5inv.*' + [regex]::Escape($r5)) 45)

# --- 4. decline
$r6 = Get-Random
$decName = "m5dec$r6"
$peerOut = Invoke-Peer @('mkinvite', $decName, $mxid)
$decRoom = if ($peerOut -match '(?m)^CREATED (\S+) ') { $matches[1] } else { $null }
Check 'decline room created' ($null -ne $decRoom)
Check 'decline invite prompted' (Wait-For ('NOTICE m2078 :invite #\d+: ' + [regex]::Escape($decName)) 30)
$invN3 = $null
if ($out.ToString() -match ('(?s).*invite #(\d+): ' + [regex]::Escape($decName))) { $invN3 = $matches[1] }
if ($invN3) {
    $w.WriteLine("PRIVMSG &matrix :decline $invN3")
    Check 'invite declined' (Wait-For ('NOTICE m2078 :declined ' + [regex]::Escape($decName)) 30)
}

$w.WriteLine('QUIT :bye')
Start-Sleep 1
try { $c.Close() } catch {}
[IO.File]::WriteAllText($OutFile, $out.ToString())
$total = 0; $failed = 0
foreach ($line in ($checks.ToString() -split "`r?`n")) {
    if ($line -match '^(\w+) (.*)$') {
        $total++
        if ($matches[1] -ne 'PASS') { $failed++ }
    }
}
Write-Host ""
Write-Host "irc log: $OutFile"
if ($failed -gt 0) { Write-Host "$failed of $total checks FAILED" -ForegroundColor Red; exit 1 }
Write-Host "all $total checks passed" -ForegroundColor Green
