# M4 e2e: formatting both ways, replies, reactions, edits/redactions, mentions.
# Requires a running matrix2078 (rebuilt with M4) and dev/test-creds.env.
param(
    [int]$Port = 2078,
    [int]$TimeoutSec = 180,
    [string]$OutFile = "$env:TEMP\opencode\irc-m4.log"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$pass = $creds['MATRIX2078_IT_PASS']
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

# --- 1. register with caps (message-tags for TAGMSG/reply tags, redaction cap)
$w.WriteLine('CAP LS 302')
$w.WriteLine('CAP REQ :server-time message-tags batch echo-message draft/message-redaction')
$w.WriteLine("PASS $pass")
$w.WriteLine('NICK m2078')
$w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
$w.WriteLine('CAP END')
Check 'welcome 001' (Wait-For ' 001 ' 30)
Check 'JOIN burst' (Wait-For '(?m)^:matrix2078 332 m2078 #\S+ :.*' 20)

$plainChan = $null
foreach ($m in [regex]::Matches($out.ToString(), '(?m)332 m2078 (#\S+) :(.*)$')) {
    if ($m.Groups[2].Value -match '!rUL1FW6b5oVOa4GnkX') { $plainChan = $m.Groups[1].Value }
}
if (-not $plainChan) {
    foreach ($m in [regex]::Matches($out.ToString(), '(?m)332 m2078 (#\S+) :')) {
        if ($m.Groups[1].Value -match 'plain') { $plainChan = $m.Groups[1].Value }
    }
}
Check 'found plain room channel' ($null -ne $plainChan)
if ($null -eq $plainChan) { $plainChan = '#m2078-plain' }
$w.WriteLine("JOIN $plainChan")

# --- 2. Matrix -> IRC formatting (HTML with bold + color)
$html = '<b>bold</b> and <font data-mx-color="#FF0000">red</font>'
$stamp1 = "fmt $(Get-Random)"
$peerOut = Invoke-Peer @('format', $roomPlain, "$stamp1 $html")
Check 'peer sent formatted event' ($peerOut -match '(?m)^SENT \$')
$ev1 = if ($peerOut -match '(?m)^SENT \$(\S+)') { $matches[1] } else { $null }
Check 'bold rendered as 0x02' ($ev1 -and (Wait-For ([regex]::Escape($stamp1) + '.*\x02bold\x02') 30))
Check 'color rendered as 0x04' (Wait-For '\x04FF0000red\x03' 10)

# --- 3. IRC -> Matrix formatting (mIRC codes -> formatted_body)
$stamp2 = "ircfmt $(Get-Random)"
$w.WriteLine("PRIVMSG $plainChan :$stamp2 :$([char]2)bold$([char]2) plain")
Check 'echo shows own message' (Wait-For ([regex]::Escape($stamp2)) 20)
Start-Sleep 3
$rd = Invoke-Peer @('read', $roomPlain, '6')
Check 'peer sees formatted_body' ($rd -match [regex]::Escape("$stamp2") -and $rd -match '<b>bold</b>')

# --- 4. replies both ways
# Matrix -> IRC: +draft/reply tag, no "> " fallback
$peerOut = Invoke-Peer @('reply', $roomPlain, "`$$ev1", 'reply body here')
Check 'peer sent reply' ($peerOut -match '(?m)^SENT \$')
$ev2 = if ($peerOut -match '(?m)^SENT \$(\S+)') { $matches[1] } else { $null }
Check 'reply relayed with draft/reply tag' ($ev2 -and (Wait-For ([regex]::Escape("msgid=$ev2") + '.*\+draft/reply=\$' + [regex]::Escape($ev1) + '.*reply body here') 30))
Check 'reply fallback stripped' (-not ($out.ToString() -match [regex]::Escape('> <@')))
# IRC -> Matrix: PRIVMSG with +draft/reply tag
$stamp3 = "irc-reply $(Get-Random)"
$w.WriteLine("@+draft/reply=`$$ev1 PRIVMSG $plainChan :$stamp3")
Check 'reply echo' (Wait-For ([regex]::Escape($stamp3)) 20)
Start-Sleep 3
$rd = Invoke-Peer @('read', $roomPlain, '6')
Check 'matrix reply relation set' ($rd -match ('(?s)' + [regex]::Escape($stamp3) + '.*m\.in_reply_to.*' + [regex]::Escape($ev1)))

# --- 5. reactions both ways
$thumb = [char]::ConvertFromUtf32(0x1F44D)
$reactKey = "m4r$(Get-Random)"
# Matrix -> IRC: TAGMSG with +draft/react
Invoke-Peer @('react', $roomPlain, "`$$ev1", $reactKey) | Out-Null
Check 'reaction relayed as TAGMSG' (Wait-For ([regex]::Escape("+draft/reply=`$$ev1") + '.*\+draft/react=' + [regex]::Escape($reactKey)) 30)
# IRC -> Matrix: TAGMSG with both tags (unique key to avoid M_DUPLICATE_ANNOTATION)
$w.WriteLine("@+draft/reply=`$$ev1;+draft/react=$reactKey TAGMSG $plainChan")
Start-Sleep 5
$rd = Invoke-Peer @('read', $roomPlain, '8')
Check 'matrix reaction annotation' ($rd -match ('(?s)m\.reaction.*' + [regex]::Escape($ev1) + '.*' + [regex]::Escape($reactKey)))

# --- 6. edits (Matrix -> IRC): "* new body"
$peerOut = Invoke-Peer @('edit', $roomPlain, "`$$ev1", 'edited body now')
Check 'peer sent edit' ($peerOut -match '(?m)^SENT \$')
$ev3 = if ($peerOut -match '(?m)^SENT \$(\S+)') { $matches[1] } else { $null }
Check 'edit relayed as * line' ($ev3 -and (Wait-For ([regex]::Escape("msgid=$ev3") + '.*PRIVMSG [^ ]+ :\* edited body now') 30))

# --- 7. redactions both ways
# Matrix -> IRC: REDACT line (cap negotiated)
$peerOut = Invoke-Peer @('redact', $roomPlain, "`$$ev1", 'cleanup')
Check 'peer redacted' ($peerOut -match '(?m)^REDACTED')
Check 'redaction relayed as REDACT' (Wait-For ([regex]::Escape("REDACT $plainChan ") + '\$' + [regex]::Escape($ev1) + ' :?cleanup') 30)
# IRC -> Matrix: REDACT command
$w.WriteLine("REDACT $plainChan `$$ev2 oops")
Start-Sleep 3
$rd = Invoke-Peer @('read', $roomPlain, '6')
Check 'matrix redaction event' ($rd -match ('(?s)m\.room\.redaction.*' + [regex]::Escape($ev2)))

# --- 8. mentions both ways
# IRC -> Matrix: nick mention -> m.mentions
$stamp4 = "mention $(Get-Random)"
$w.WriteLine("PRIVMSG $plainChan :m2078-peer $stamp4")
Check 'mention echo' (Wait-For ([regex]::Escape($stamp4)) 20)
Start-Sleep 3
$rd = Invoke-Peer @('read', $roomPlain, '6')
Check 'm.mentions user_ids set' ($rd -match ('(?s)' + [regex]::Escape($stamp4) + '.*m\.mentions.*m2078-peer'))
# Matrix -> IRC: @mxid replaced by nick
$peerMxid = "@$($peer['E2E_PEER_USER']):doesnmlab.xyz"
$peerOut = Invoke-Peer @('mention', $roomPlain, '@m2078:doesnmlab.xyz', "hey @m2078:doesnmlab.xyz ping $stamp4")
Check 'peer sent mention' ($peerOut -match '(?m)^SENT \$')
Check 'mxid localized to nick' (Wait-For ('m2078 ping ' + [regex]::Escape($stamp4)) 30)

$w.WriteLine('QUIT :bye')
Start-Sleep 1
try { $c.Close() } catch {}
Read-Available
[IO.File]::WriteAllText($OutFile, $out.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Host '---'
$checks.ToString().TrimEnd()
$fails = ([regex]::Matches($checks.ToString(), 'FAIL')).Count
if ($fails -gt 0) { exit 1 } else { exit 0 }
