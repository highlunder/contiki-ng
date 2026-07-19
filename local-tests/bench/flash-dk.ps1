# flash-dk.ps1 - flash the nRF52840-DKs by board label (A/B) with nrfjprog,
# and (flash-and-read variants) open the DK's serial console with auto-reconnect.
# Dot-source it in PowerShell, then call the functions:
#     . \\wsl.localhost\Ubuntu\home\joel\gemini_workspace\contiki-ng\local-tests\bench\flash-dk.ps1
#
#   Flash only:
#     Flash-Enroll c509 / x509          # H2 (A=server, B=client)
#     Flash-H6 c5t 3 / x5c 3            # H6 (A=root, B=leaf) + prints relay cmds
#     Flash-DK A <hex>                  # low-level
#   Flash AND read the DUT serial (auto-reopens across the DK reset, Ctrl+C to stop):
#     Enroll-Read c509 / x509           # flashes both DKs, then reads DK-B (client)
#     H6-Read c5t 3 / x5c 3            # flashes A+B, then reads DK-B (leaf)
#     Flash-Read B <hex> [-Port COMx]   # flash one DK + read it
#     Read-COM COM4                     # just read a port (no flash)

# --- DK board label -> J-Link serial number -------------------------------
$Global:DK = @{ A = "683609980"; B = "1050212677" }

# --- WSL repo root as seen from Windows (edit <distro> if not Ubuntu:  wsl -l -q)
$Global:C = "\\wsl.localhost\Ubuntu\home\joel\gemini_workspace\contiki-ng"

# Unlock a DK with readback/AP protection enabled (full erase + disable APPROTECT).
# Needed once for a board that reports error -90 / "Access protection is enabled".
function Recover-DK {
    param([Parameter(Mandatory)][ValidateSet('A','B')][string]$Board)
    $sn = $DK[$Board]
    Write-Host "== DK-$Board  (SN $sn)  RECOVER  (erase + disable APPROTECT)" -ForegroundColor Magenta
    nrfjprog -f NRF52 --snr $sn --recover
}

function Flash-DK {
    param(
        [Parameter(Mandatory)][ValidateSet('A','B')][string]$Board,
        [Parameter(Mandatory)][string]$Hex,   # relative to $C, or an absolute path
        [switch]$NoRecover                     # skip the auto-recover-and-retry on failure
    )
    $sn = $DK[$Board]
    $path = if (Test-Path -LiteralPath $Hex) { $Hex } else { Join-Path $C $Hex }
    if (-not (Test-Path -LiteralPath $path)) { Write-Error "hex not found: $path"; return }
    Write-Host "== DK-$Board  (SN $sn)  <-  $path" -ForegroundColor Cyan
    nrfjprog -f NRF52 --snr $sn --program $path --chiperase --reset
    if ($LASTEXITCODE -ne 0 -and -not $NoRecover) {
        Write-Host "  program failed (exit $LASTEXITCODE) -- likely readback protection; recovering + retrying..." -ForegroundColor Yellow
        Recover-DK $Board
        nrfjprog -f NRF52 --snr $sn --program $path --chiperase --reset
    }
}

# Map a J-Link serial number to its "JLink CDC UART Port (COMx)" -> COMx.
function Get-DKPort {
    param([Parameter(Mandatory)][string]$Sn)
    Get-PnpDevice -Class Ports -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object {
        $parent = (Get-PnpDeviceProperty -InstanceId $_.InstanceId `
                   -KeyName 'DEVPKEY_Device_Parent' -ErrorAction SilentlyContinue).Data
        if (($_.InstanceId -match $Sn) -or ($parent -match $Sn)) {
            if ($_.FriendlyName -match '\((COM\d+)\)') { $Matches[1] }
        }
    } | Select-Object -First 1
}

# Read a serial port, reopening automatically when the DK re-enumerates. Ctrl+C stops.
function Read-COM {
    param([Parameter(Mandatory)][string]$Port, [int]$Baud = 115200)
    Write-Host "Reading $Port @ $Baud  (Ctrl+C to stop)" -ForegroundColor Green
    while ($true) {
        $p = $null
        try {
            $p = [System.IO.Ports.SerialPort]::new($Port, $Baud)
            $p.Open()
            Write-Host "[$Port open]" -ForegroundColor DarkGray
            while ($p.IsOpen) {
                Write-Host -NoNewline $p.ReadExisting()   # throws if the device drops
                Start-Sleep -Milliseconds 50
            }
        } catch {
            Start-Sleep -Milliseconds 500                 # not present yet / re-enumerating -> retry
        } finally {
            if ($p) { if ($p.IsOpen) { $p.Close() }; $p.Dispose() }
        }
    }
}

# Flash one DK and then read its console (auto-detect the port from the SN, or pass -Port).
function Flash-Read {
    param(
        [Parameter(Mandatory)][ValidateSet('A','B')][string]$Board,
        [Parameter(Mandatory)][string]$Hex,
        [string]$Port,
        [int]$Baud = 115200
    )
    Flash-DK $Board $Hex
    if (-not $Port) { $Port = Get-DKPort $DK[$Board] }
    if (-not $Port) {
        Write-Warning ("Could not auto-detect the COM port for DK-$Board (SN $($DK[$Board])). " +
            "Re-run with -Port COMx. Present ports: " +
            (([System.IO.Ports.SerialPort]::GetPortNames()) -join ', '))
        return
    }
    Start-Sleep -Seconds 2                                 # let the --reset re-enumerate
    Read-COM $Port $Baud
}

# H2 enrollment: A=server, B=client. Flash both, then read the client (prints [ENROLL-TIMING]).
function Flash-Enroll {
    param([Parameter(Mandatory)][ValidateSet('c509','x509')][string]$Arm)
    Flash-DK A "local-tests\bench\hw-enroll\enroll-$Arm-server-dk.hex"
    Flash-DK B "local-tests\bench\hw-enroll\enroll-$Arm-client-dk.hex"
    Write-Host "Read DK-B (client) @115200 for [ENROLL-TIMING ... arm:$Arm ...]" -ForegroundColor Yellow
}
function Enroll-Read {
    param([Parameter(Mandatory)][ValidateSet('c509','x509')][string]$Arm)
    Flash-DK A "local-tests\bench\hw-enroll\enroll-$Arm-server-dk.hex"
    Flash-Read B "local-tests\bench\hw-enroll\enroll-$Arm-client-dk.hex"
}

# H6 multi-hop: A=root (role 1), B=leaf (role hops+1); relays (roles 2..hops) = dongles (WSL DFU).
function Show-H6Relays {
    param([int]$Hops)
    if ($Hops -ge 2) {
        Write-Host "Relays (DFU from WSL, one dongle each):" -ForegroundColor Yellow
        for ($r = 2; $r -le $Hops; $r++) {
            Write-Host "  nrfutil pkg generate --hw-version 52 --sd-req 0x00 --debug-mode --application /home/joel/gemini_workspace/contiki-ng/local-tests/multihop/fw-hw/relay-r$r-dongle.hex /tmp/relay-r$r.zip"
            Write-Host "  nrfutil dfu usb-serial -pkg /tmp/relay-r$r.zip -p /dev/ttyACM0"
        }
    }
}
function Flash-H6 {
    param(
        [Parameter(Mandatory)][ValidateSet('c5t','x5c')][string]$Arm,
        [Parameter(Mandatory)][ValidateRange(1,3)][int]$Hops
    )
    $leaf = $Hops + 1
    Flash-DK A "local-tests\multihop\fw-hw\$Arm-server-r1-dk.hex"
    Flash-DK B "local-tests\multihop\fw-hw\$Arm-leaf-r$leaf-dk.hex"
    Show-H6Relays $Hops
    Write-Host "Read DK-B (leaf) @115200 for [BENCH ... FINAL] (ms) / delivery" -ForegroundColor Yellow
}
function H6-Read {
    param(
        [Parameter(Mandatory)][ValidateSet('c5t','x5c')][string]$Arm,
        [Parameter(Mandatory)][ValidateRange(1,3)][int]$Hops
    )
    $leaf = $Hops + 1
    Flash-DK A "local-tests\multihop\fw-hw\$Arm-server-r1-dk.hex"
    Show-H6Relays $Hops
    if ($Hops -ge 2) { Read-Host "Flash the relay dongle(s) from WSL (cmds above), then press Enter to flash+read the leaf" | Out-Null }
    Flash-Read B "local-tests\multihop\fw-hw\$Arm-leaf-r$leaf-dk.hex"
}

Write-Host "Loaded. Flash: Flash-Enroll <c509|x509>, Flash-H6 <c5t|x5c> <1-3>, Flash-DK <A|B> <hex>." -ForegroundColor Green
Write-Host "A locked board (error -90) auto-recovers on first flash; or run Recover-DK <A|B> manually." -ForegroundColor Green
Write-Host "Flash+read: Enroll-Read <c509|x509>, H6-Read <c5t|x5c> <1-3>, Flash-Read <A|B> <hex>, Read-COM COMx." -ForegroundColor Green
Write-Host "DK A=$($DK.A)  B=$($DK.B)" -ForegroundColor Green
