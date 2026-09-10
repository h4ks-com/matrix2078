# Live session: connect, register, keep reading for N seconds, dump to a file.
param(
    [int]$Port = 2078,
    [int]$HoldSec = 20,
    [string]$OutFile = "$env:TEMP\opencode\irc-live.log"
)

$pass = (Select-String -Path 'D:\matrix2078\dev\test-creds.env' -Pattern '^MATRIX2078_IT_PASS=(.+)$').Matches[0].Groups[1].Value

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

$w.WriteLine("PASS $pass")
$w.WriteLine('NICK m2078')
$w.WriteLine('USER @m2078:doesnmlab.xyz 0 * :m2078 live test')

$deadline = (Get-Date).AddSeconds($HoldSec)
while ((Get-Date) -lt $deadline) {
    Read-Available
    Start-Sleep -Milliseconds 200
}
$c.Close()
$out.ToString() | Set-Content -Path $OutFile -Encoding UTF8
