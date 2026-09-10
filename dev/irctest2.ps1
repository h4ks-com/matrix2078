param(
    [int]$Port = 2078,
    [string[]]$Script = @(),
    [int]$TimeoutSec = 8,
    [int]$LineDelayMs = 300
)

# Connect, run lines, print everything received until timeout.
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

foreach ($line in $Script) {
    $w.WriteLine($line)
    Start-Sleep -Milliseconds $LineDelayMs
    Read-Available
}
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline) {
    Read-Available
    if (-not $c.Connected) { break }
    Start-Sleep -Milliseconds 200
}
$c.Close()
$out.ToString()
