<#
  watch-serial.ps1 -- read an nRF52840-DK serial console on Windows, prefix each
  line with a wall-clock timestamp AND the delta since the previous line, and tee
  everything to a log file.

  Replaces `plink -serial COM5 -sercfg 115200,8,n,1,N` (only one process can own
  the COM port at a time, so close plink first). plink cannot timestamp its output.

  Why the delta column: the gap between two [BENCH ...] lines is the benchmark's
  (untimed) inter-iteration settle -- NOT the handshake, which is the ~3 s number
  inside the line. The "(+NN.Ns)" makes that obvious, and makes a real stall (a
  failed iteration re-trying, or RPL healing) stand out from a normal settle.

  Reads the port directly via System.IO.Ports.SerialPort so each line is stamped
  the instant it arrives -- no plink pipe buffering to smear the timestamps.

  Usage (Windows PowerShell, from wherever you keep it, e.g. copy out of
  \\wsl.localhost\Ubuntu\home\joel\gemini_workspace\contiki-ng\local-tests\bench\):
    .\watch-serial.ps1 -Port COM5
    .\watch-serial.ps1 -Port COM5 -Baud 115200 -Log dtls-x509-run1.log
  Ctrl-C to stop. If you see the header but no data, the board may gate TX on DTR
  -- it is already asserted below; otherwise re-seat / re-flash and check the port.

  SECURITY NOTICE: Test credentials only. Never use in production.
#>
param(
  [string]$Port = "COM5",
  [int]$Baud    = 115200,
  [string]$Log  = ""
)

if ([string]::IsNullOrEmpty($Log)) {
  $Log = "bench-{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmmss")
}

$sp = New-Object System.IO.Ports.SerialPort $Port, $Baud,
        ([System.IO.Ports.Parity]::None), 8, ([System.IO.Ports.StopBits]::One)
$sp.ReadTimeout = 500          # ms; lets Ctrl-C break the loop between lines
$sp.NewLine     = "`n"         # Contiki prints '\n'; we strip any trailing '\r'
$sp.DtrEnable   = $true        # some CDC/VCP stacks gate TX on DTR; harmless here
$sp.RtsEnable   = $true

$sp.Open()
Write-Host ("# {0}  logging {1} @ {2} -> {3}  (Ctrl-C to stop)" -f `
            (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Port, $Baud, $Log)
$last = Get-Date
try {
  while ($true) {
    try   { $line = $sp.ReadLine() }
    catch [System.TimeoutException] { continue }
    $now  = Get-Date
    $dt   = ($now - $last).TotalSeconds
    $last = $now
    $out  = "{0:HH:mm:ss.fff} (+{1,6:N1}s)  {2}" -f $now, $dt, $line.TrimEnd("`r")
    Write-Host $out
    Add-Content -LiteralPath $Log -Value $out
  }
}
finally {
  $sp.Close()
  Write-Host ("# closed {0}" -f $Port)
}
