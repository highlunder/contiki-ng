# flash-dk.ps1 - flash the nRF52840-DKs by board label (A/B) with nrfjprog.
# Dot-source it in PowerShell to load the helpers, then call the functions:
#     . \\wsl.localhost\Ubuntu\home\joel\gemini_workspace\contiki-ng\local-tests\bench\flash-dk.ps1
#     Flash-Enroll c509      # H2 C509 arm  (A=server, B=client)
#     Flash-Enroll x509      # H2 X.509 arm
#     Flash-H6 c5t 3         # H6 c5t arm, 3 hops (A=root, B=leaf) + prints relay cmds
#     Flash-DK A local-tests\bench\hw-enroll\enroll-c509-server-dk.hex   # low-level

# --- DK board label -> J-Link serial number -------------------------------
$Global:DK = @{ A = "683609980"; B = "1050212677" }

# --- WSL repo root as seen from Windows (edit <distro> if not Ubuntu:  wsl -l -q)
$Global:C = "\\wsl.localhost\Ubuntu\home\joel\gemini_workspace\contiki-ng"

function Flash-DK {
    param(
        [Parameter(Mandatory)][ValidateSet('A','B')][string]$Board,
        [Parameter(Mandatory)][string]$Hex   # relative to $C, or an absolute path
    )
    $sn = $DK[$Board]
    $path = if (Test-Path -LiteralPath $Hex) { $Hex } else { Join-Path $C $Hex }
    if (-not (Test-Path -LiteralPath $path)) { Write-Error "hex not found: $path"; return }
    Write-Host "== DK-$Board  (SN $sn)  <-  $path" -ForegroundColor Cyan
    nrfjprog -f NRF52 --snr $sn --program $path --chiperase --reset
}

# H2 enrollment: A = server (root/CA), B = client (DUT). Arm = c509 | x509.
function Flash-Enroll {
    param([Parameter(Mandatory)][ValidateSet('c509','x509')][string]$Arm)
    Flash-DK A "local-tests\bench\hw-enroll\enroll-$Arm-server-dk.hex"
    Flash-DK B "local-tests\bench\hw-enroll\enroll-$Arm-client-dk.hex"
    Write-Host "Read DK-B (client) serial @115200 for [ENROLL-TIMING ... arm:$Arm ...]" -ForegroundColor Yellow
}

# H6 multi-hop: A = root (role 1), B = leaf (role hops+1). Arm = c5t | x5c.
# Relays (roles 2..hops) are dongles -> flashed from WSL; the commands are printed.
function Flash-H6 {
    param(
        [Parameter(Mandatory)][ValidateSet('c5t','x5c')][string]$Arm,
        [Parameter(Mandatory)][ValidateRange(1,3)][int]$Hops
    )
    $leaf = $Hops + 1
    Flash-DK A "local-tests\multihop\fw-hw\$Arm-server-r1-dk.hex"
    Flash-DK B "local-tests\multihop\fw-hw\$Arm-leaf-r$leaf-dk.hex"
    if ($Hops -ge 2) {
        Write-Host "Relays (DFU from WSL, one dongle each):" -ForegroundColor Yellow
        for ($r = 2; $r -le $Hops; $r++) {
            Write-Host "  nrfutil pkg generate --hw-version 52 --sd-req 0x00 --debug-mode --application /home/joel/gemini_workspace/contiki-ng/local-tests/multihop/fw-hw/relay-r$r-dongle.hex /tmp/relay-r$r.zip"
            Write-Host "  nrfutil dfu usb-serial -pkg /tmp/relay-r$r.zip -p /dev/ttyACM0"
        }
    }
    Write-Host "Read DK-B (leaf) serial @115200 for [BENCH ... FINAL] (ms) / delivery" -ForegroundColor Yellow
}

Write-Host "Loaded: Flash-DK <A|B> <hex>, Flash-Enroll <c509|x509>, Flash-H6 <c5t|x5c> <1-3>.  DK A=$($DK.A) B=$($DK.B)" -ForegroundColor Green
