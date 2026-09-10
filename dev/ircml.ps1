# Focused multiline repro: send a draft/multiline batch, watch for echo.
param([int]$Port = 2078, [int]$HoldSec = 45)

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
function Read-Available {
    while ($s.DataAvailable) {
        $n = $s.Read($buf, 0, 16384)
        if ($n -le 0) { break }
        [void]$out.Append([Text.Encoding]::UTF8.GetString($buf, 0, $n))
    }
}
$w.WriteLine('CAP LS 302')
$w.WriteLine('CAP REQ :server-time echo-message message-tags batch draft/multiline')
$w.WriteLine("PASS $pass")
$w.WriteLine('NICK m2078')
$w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
$w.WriteLine('CAP END')
$deadline = (Get-Date).AddSeconds(12)
while ((Get-Date) -lt $deadline) { Read-Available; Start-Sleep -Milliseconds 200 }
$w.WriteLine('BATCH +t1 draft/multiline #m2078-plain')
$w.WriteLine('@draft/multiline=t1 PRIVMSG #m2078-plain :first line')
$w.WriteLine('@draft/multiline=t1 PRIVMSG #m2078-plain :second line')
$w.WriteLine('BATCH -t1')
$deadline = (Get-Date).AddSeconds($HoldSec)
while ((Get-Date) -lt $deadline) { Read-Available; Start-Sleep -Milliseconds 200 }
$c.Close()
$out.ToString() | Set-Content -Path "$env:TEMP\opencode\irc-ml.log" -Encoding UTF8
# show only the interesting tail
($out.ToString() -split "`r`n" | Select-String -Pattern 'BATCH|first|second') | ForEach-Object { $_.Line }
