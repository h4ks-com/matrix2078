# M2 e2e: CAP negotiation, SASL PLAIN, echo-message, msgid/time tags,
# multiline batches both ways, CHATHISTORY. Requires a running matrix2078.
param(
    [int]$Port = 2078,
    [int]$TimeoutSec = 90,
    [string]$OutFile = "$env:TEMP\opencode\irc-m2.log"
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$pass = $creds['MATRIX2078_IT_PASS']

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

# --- 1. CAP LS 302
$w.WriteLine('CAP LS 302')
Check 'CAP LS lists caps' (Wait-For 'CAP \* LS :.*server-time' 5)
Check 'CAP LS has sasl=PLAIN' ($out.ToString() -match 'sasl=PLAIN')
Check 'CAP LS has draft/chathistory' ($out.ToString() -match 'draft/chathistory')

# --- 2. CAP REQ
$w.WriteLine('CAP REQ :server-time echo-message message-tags batch draft/chathistory draft/multiline away-notify account-notify')
Check 'CAP REQ ACKed' (Wait-For 'CAP \* ACK :server-time echo-message' 5)

# --- 3. SASL PLAIN (user = full mxid)
$w.WriteLine('AUTHENTICATE PLAIN')
Check 'AUTHENTICATE challenge' (Wait-For 'AUTHENTICATE \+' 5)
$sasl = "`0@m2078:doesnmlab.xyz`0$pass"
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($sasl))
$w.WriteLine("AUTHENTICATE $b64")
Check 'SASL 900 logged in' (Wait-For ' 900 ' 5)
Check 'SASL 903 success' ($out.ToString() -match ' 903 ')

# --- 4. register
$w.WriteLine('NICK m2078')
$w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
$w.WriteLine('CAP END')
Check 'welcome 001' (Wait-For ' 001 ' 30)
Check 'JOIN burst' (Wait-For ':m2078!.*JOIN #m2078-plain' 20)

# --- 5. echo-message with msgid
$w.WriteLine('PRIVMSG #m2078-plain :echo test m2')
Check 'echo-message with msgid+time tags' (Wait-For '@time=[^;]+;msgid=[^ ]+ :m2078!m@matrix2078 PRIVMSG #m2078-plain :echo test m2' 20)

# --- 6. multiline batch to matrix
$w.WriteLine('BATCH +t1 draft/multiline #m2078-plain')
$w.WriteLine('@draft/multiline=t1 PRIVMSG #m2078-plain :first line')
$w.WriteLine('@draft/multiline=t1 PRIVMSG #m2078-plain :second line')
$w.WriteLine('BATCH -t1')
Check 'multiline batch echoed' (Wait-For '(?s)@time=[^;]+;msgid=[^;]+;draft/multiline=m\.\S+ :m2078!m@matrix2078 PRIVMSG #m2078-plain :first line' 20)
Check 'multiline echo carries both lines' ($out.ToString() -match '(?s)draft/multiline=m\.\S+ :m2078!m@matrix2078 PRIVMSG #m2078-plain :second line')

# --- 7. CHATHISTORY LATEST
$w.WriteLine('CHATHISTORY LATEST #m2078-plain * 10')
Check 'chathistory batch' (Wait-For 'BATCH \+\S+ chathistory #m2078-plain' 20)
Check 'chathistory contains our echo' (Wait-For '@time=[^;]+;msgid=[^ ]+ :m2078-peer!matrix@matrix PRIVMSG #m2078-plain' 60)

# --- 8. CHATHISTORY BEFORE with a msgid anchor
$msgid = $null
if ($out.ToString() -match 'msgid=([A-Za-z0-9_\-]+) :m2078-peer') { $msgid = $matches[1] }
if ($msgid) {
    $w.WriteLine("CHATHISTORY BEFORE #m2078-plain msgid=$msgid 5")
    Check 'chathistory BEFORE batch' (Wait-For 'BATCH \+\S+ chathistory #m2078-plain' 20)
} else {
    Check 'found msgid anchor for BEFORE' $false
}

# --- 9. CHATHISTORY TARGETS
$w.WriteLine('CHATHISTORY TARGETS 10')
Check 'chathistory targets 272' (Wait-For ' 272 m2078 #' 10)

# --- 10. peer sends a message; expect relay with tags
$hs = 'https://matrix.doesnmlab.xyz'
$login = @{
    type = 'm.login.password'
    identifier = @{ type = 'm.id.user'; user = $creds['MATRIX2078_IT_PEER_USER'] }
    password = $creds['MATRIX2078_IT_PEER_PASS']
} | ConvertTo-Json -Depth 5 -Compress
$loginResp = Invoke-RestMethod -Method Post -Uri "$hs/_matrix/client/v3/login" -Body $login -ContentType 'application/json'
$tok = $loginResp.access_token
$room = '!rUL1FW6b5oVOa4GnkX%3Adoesnmlab.xyz'
$msg1 = "peer m2 relay check $(Get-Date -Format HHmmss)"
$body = '{"msgtype":"m.text","body":"' + $msg1 + '"}'
$txn = "m2e2e$(Get-Date -Format yyyyMMddHHmmss)"
Invoke-RestMethod -Method Put -Uri "$hs/_matrix/client/v3/rooms/$room/send/m.room.message/$txn`?access_token=$tok" -Body $body -ContentType 'application/json' | Out-Null
Check 'peer relay with time+msgid' (Wait-For '@time=[^;]+;msgid=[^ ]+ :m2078-peer!matrix@matrix PRIVMSG #m2078-plain :peer m2 relay check' 30)

# --- 11. peer sends multiline; expect draft/multiline batch downstream
$body2 = '{"msgtype":"m.text","body":"peer multi head\npeer multi tail"}'
$txn2 = "m2e2em$(Get-Date -Format yyyyMMddHHmmss)"
Invoke-RestMethod -Method Put -Uri "$hs/_matrix/client/v3/rooms/$room/send/m.room.message/$txn2`?access_token=$tok" -Body $body2 -ContentType 'application/json' | Out-Null
Check 'peer multiline batch down' (Wait-For 'BATCH \+m\.\S+ draft/multiline #m2078-plain' 30)
Check 'peer multiline lines relayed' (Wait-For '(?s)@time=[^;]+;msgid=[^;]+;draft/multiline=m\.\S+ :m2078-peer!matrix@matrix PRIVMSG #m2078-plain :peer multi tail' 15)

$c.Close()
New-Item -ItemType Directory -Force -Path (Split-Path $OutFile) | Out-Null
$out.ToString() | Set-Content -Path $OutFile -Encoding UTF8
''
$checks.ToString()
