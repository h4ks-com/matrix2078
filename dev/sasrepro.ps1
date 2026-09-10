# Focused M3 SAS repro: connect, accept, dump peer stdout live.
param([int]$Port = 2078)
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$creds = @{}
Get-Content 'D:\matrix2078\dev\test-creds.env' | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { $creds[$matches[1]] = $matches[2] }
}
$pass = $creds['MATRIX2078_IT_PASS']

$t0 = Get-Date
$c = New-Object Net.Sockets.TcpClient('127.0.0.1', $Port)
$s = $c.GetStream()
$w = New-Object IO.StreamWriter($s)
$w.AutoFlush = $true; $w.NewLine = "`r`n"
$buf = New-Object byte[] 16384
$out = New-Object System.Text.StringBuilder
function Read-Available { while ($s.DataAvailable) { $n = $s.Read($buf,0,16384); if ($n -le 0) {break}; [void]$out.Append([Text.Encoding]::UTF8.GetString($buf,0,$n)) } }
function Wait-For([string]$p,[int]$sec) { $d=(Get-Date).AddSeconds($sec); while((Get-Date) -lt $d){ Read-Available; if($out.ToString() -match $p){return $true}; Start-Sleep -Milliseconds 150 }; return $false }

$w.WriteLine("PASS $pass"); $w.WriteLine('NICK m2078'); $w.WriteLine('USER m 0 * :https://matrix.doesnmlab.xyz')
[void](Wait-For ' 001 ' 60)
"t+001: $(((Get-Date)-$t0).TotalSeconds -as [int])s"

# peer requests verification towards us
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = 'D:\matrix2078\target\debug\e2e_peer.exe'
$psi.Arguments = 'request "@m2078:doesnmlab.xyz"'
$psi.EnvironmentVariables['E2E_PEER_HOMESERVER'] = 'https://matrix.doesnmlab.xyz'
$psi.EnvironmentVariables['E2E_PEER_USER'] = $creds['MATRIX2078_IT_PEER_USER']
$psi.EnvironmentVariables['E2E_PEER_PASS'] = $creds['MATRIX2078_IT_PEER_PASS']
$psi.EnvironmentVariables['E2E_PEER_STATE'] = 'D:\matrix2078\dev\state-peer'
$psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.UseShellExecute = $false
$peer = [Diagnostics.Process]::Start($psi)

if (Wait-For 'verification request from @m2078-peer' 45) {
    'NOTICE seen'
    $w.WriteLine('PRIVMSG &matrix :verify accept')
    if (Wait-For 'SAS for @m2078-peer' 45) { 'SAS SEEN'; $w.WriteLine('PRIVMSG &matrix :verify match') } else { 'SAS MISSING' }
} else { 'NO REQUEST NOTICE' }
[void](Wait-For 'verification with @m2078-peer done' 20)
$w.WriteLine('QUIT')
Start-Sleep 2
Read-Available
# dump the tail of the IRC stream
$out.ToString().Split("`n") | Select-Object -Last 25
'--- peer stdout ---'
$peer.Kill()
$peer.StandardOutput.ReadToEnd()
