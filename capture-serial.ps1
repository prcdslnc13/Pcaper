<#
.SYNOPSIS
    Capture USB traffic for a USB serial device (USBPcap + tshark), then check
    the capture actually contains that device's traffic.

.DESCRIPTION
    Finds which USBPcap interface carries a given USB serial device, captures
    that interface to a timestamped pcapng, and reports what the file holds:
    whether the device was seen, whether the port was opened, whether any
    serial bytes flowed. An empty capture is diagnosed on the spot instead of
    being discovered later in Wireshark.

    USBPcap attaches per root hub, not per device, so the interface number is a
    property of which physical port the device is plugged into -- it changes if
    the cable moves. This resolves it at run time rather than making you guess,
    and refuses to capture rather than silently recording the wrong hub.

    tshark launches USBPcapCMD with whatever options are saved in Wireshark's
    preferences file for that interface. If "capture from all devices" was ever
    unticked in the Wireshark GUI, every later capture on that interface --
    from the GUI or from tshark -- records nothing at all, not even the device
    descriptors. This script overrides those preferences for its own run and
    warns when the saved values would break other tools.

    Output filenames are always timestamped: overwriting a capture you cannot
    reproduce (the machine has moved, the fault did not recur) loses the run.

.PARAMETER Port
    COM port of the device, e.g. COM10. The USB VID:PID and the USBPcap
    interface are resolved from it. Works for FTDI (FTDIBUS) and CDC (usbser)
    ports alike. Preferred over -VidPid when the machine has several adapters.

.PARAMETER VidPid
    Device to find, as hex VID:PID, e.g. 0403:6001 (FTDI FT232). Used when
    -Port is not given. Defaults to 0483:5740 (STM32 Virtual ComPort) when
    neither -Port nor -VidPid is supplied.

.PARAMETER Interface
    Skip the lookup and capture this USBPcap interface, e.g. USBPcap1. The
    device check after the capture still runs.

.PARAMETER OutDir
    Directory for the capture file. Default: current directory.

.PARAMETER Seconds
    Stop automatically after this many seconds. 0 (default) captures until you
    press Ctrl-C.

.PARAMETER RingMinutes
    Capture into a rolling ring buffer, each file covering this many minutes.
    Combined with -RingFiles this keeps a fixed window of recent history at a
    bounded disk cost, so a capture can be left running all day waiting for an
    intermittent fault instead of trying to reproduce one on demand.

.PARAMETER RingFiles
    How many ring-buffer files to keep (default 24). Total retained history is
    RingMinutes * RingFiles.

.PARAMETER Tag
    Short label folded into the filename, e.g. "hang" or "baseline".

.EXAMPLE
    .\capture-serial.ps1 -Port COM10 -Tag jog-hang

.EXAMPLE
    .\capture-serial.ps1 -VidPid 0403:6001 -Seconds 120 -Tag baseline

.EXAMPLE
    .\capture-serial.ps1 -Port COM10 -RingMinutes 5 -RingFiles 48 -Tag standing

.NOTES
    Requires an elevated shell: the USBPcap driver will not hand out a capture
    handle to a non-admin process.

    Start the capture BEFORE the application opens the port. The interesting
    part of a serial session is usually the open (baud rate, flow control,
    DTR/RTS) and a capture that starts afterwards cannot show it.
#>
[CmdletBinding()]
param(
    [string]$Port = "",
    [string]$VidPid = "",
    [string]$Interface = "",
    [string]$OutDir = ".",
    [int]$Seconds = 0,
    [int]$RingMinutes = 0,
    [int]$RingFiles = 24,
    [string]$Tag = "capture"
)

$ErrorActionPreference = "Stop"

function Fail($msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }
function Warn($msg) { Write-Host "WARNING: $msg" -ForegroundColor Yellow }

# Matches both PnP spellings: USB\VID_0403&PID_6001\... and FTDIBUS\VID_0403+PID_6001+...
$VidPidPattern = 'VID_([0-9A-Fa-f]{4})[&+]PID_([0-9A-Fa-f]{4})'

# --- preconditions -----------------------------------------------------------

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Fail "USBPcap capture requires an elevated shell. Re-run this from a terminal started with 'Run as administrator'."
}

$tshark = "C:\Program Files\Wireshark\tshark.exe"
if (-not (Test-Path $tshark)) {
    $cmd = Get-Command tshark -ErrorAction SilentlyContinue
    if (-not $cmd) { Fail "tshark not found. Install Wireshark (with USBPcap)." }
    $tshark = $cmd.Source
}
$capinfos = Join-Path (Split-Path $tshark) "capinfos.exe"

$usbpcap = "C:\Program Files\Wireshark\extcap\USBPcapCMD.exe"
if (-not (Test-Path $usbpcap)) { $usbpcap = "C:\Program Files\USBPcap\USBPcapCMD.exe" }
if (-not (Test-Path $usbpcap)) { Fail "USBPcapCMD.exe not found. Re-run the Wireshark installer and tick USBPcap." }

if ($Port -and $Port -notmatch '^COM\d+$') { Fail "-Port must look like COM10" }
if ($VidPid -and $VidPid -notmatch '^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}$') { Fail "-VidPid must look like 0403:6001" }
if ($Interface -and $Interface -notmatch '^(\\\\\.\\)?USBPcap\d+$') { Fail "-Interface must look like USBPcap1" }

# --- which device? -----------------------------------------------------------

function Get-ParentChain([string]$instanceId) {
    # Walk up the PnP tree. For a COM port this passes through the USB device
    # that owns it (and, for FTDI, the FTDIBUS enumerator in between).
    $chain = @()
    $id = $instanceId
    for ($i = 0; $i -lt 8 -and $id; $i++) {
        $parent = (Get-PnpDeviceProperty -InstanceId $id -KeyName DEVPKEY_Device_Parent `
                       -ErrorAction SilentlyContinue).Data
        if (-not $parent) { break }
        $dev = Get-PnpDevice -InstanceId $parent -ErrorAction SilentlyContinue
        if (-not $dev) { break }
        $chain += $dev
        $id = $parent
    }
    return $chain
}

$vid = $null; $pid_ = $null
$portDev = $null      # the COM port (Ports class)
$usbDev = $null       # the USB function that owns it (what the USBPcap tree names)

if ($Port) {
    $portDev = Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
               Where-Object { $_.FriendlyName -like "*($Port)" } | Select-Object -First 1
    if (-not $portDev) {
        $present = (Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
                    ForEach-Object { $_.FriendlyName }) -join ', '
        if (-not $present) { $present = '(none)' }
        Fail "No present device exposes $Port. Serial ports currently present: $present"
    }
    foreach ($dev in @($portDev) + @(Get-ParentChain $portDev.InstanceId)) {
        if ($dev.InstanceId -match $VidPidPattern) {
            if (-not $vid) { $vid = $Matches[1].ToUpper(); $pid_ = $Matches[2].ToUpper() }
            if ($dev.InstanceId -like 'USB\*') { $usbDev = $dev; break }
        }
    }
    if (-not $vid) { Fail "$Port is not a USB serial port (no VID/PID in its device path)." }
    if (-not $usbDev) { $usbDev = $portDev }
    $VidPid = "${vid}:${pid_}"
}
else {
    if (-not $VidPid) { $VidPid = "0483:5740" }
    $vid = $VidPid.Split(':')[0].ToUpper(); $pid_ = $VidPid.Split(':')[1].ToUpper()

    $usbDev = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
              Where-Object { $_.InstanceId -like "USB\VID_$vid&PID_$pid_*" } |
              Select-Object -First 1
    if (-not $usbDev) {
        Fail @"
No device matching VID_$vid&PID_$pid_ is connected.
Plug the controller in, confirm it enumerates a COM port, then re-run.
(A device that is merely remembered by Windows is not the same as one present.)
"@
    }
    # Find its COM port, if it has one, so the interface match can use it.
    $portDev = Get-PnpDevice -PresentOnly -Class Ports -ErrorAction SilentlyContinue |
               Where-Object { $_.InstanceId -match "VID_$vid[&+]PID_$pid_" } |
               Select-Object -First 1
    if ($portDev -and $portDev.FriendlyName -match '\((COM\d+)\)') { $Port = $Matches[1] }
}

Write-Host "Device   : $($usbDev.FriendlyName)  [VID:PID $VidPid]" -ForegroundColor Green
Write-Host "           $($usbDev.InstanceId)"
if ($portDev) { Write-Host "Port     : $($portDev.FriendlyName)" -ForegroundColor Green }

# --- which USBPcap interface carries it? -------------------------------------
# USBPcapCMD's extcap config lists the device tree per filter device. The tree
# names the COM port itself ("USB Serial Port (COM10)") under its USB parent
# ("[3] USB Serial Converter"), so match on the port first -- it is unique even
# when two identical adapters are attached -- and on the parent's name second.

# USBPcapCMD writes its extcap output straight to the console, which PowerShell's
# native-command redirection does not capture. Going through cmd.exe gets it.
function Get-UsbPcapInterfaces {
    cmd /c "`"$usbpcap`" --extcap-interfaces 2>&1" |
        Select-String -Pattern '\{value=(\\\\\.\\USBPcap\d+)\}' -AllMatches |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Groups[1].Value }
}

function Get-UsbPcapTree([string]$iface) {
    cmd /c "`"$usbpcap`" --extcap-interface $iface --extcap-config 2>&1"
}

function Get-TreeNames($config) {
    $config |
        Select-String -Pattern '\{display=([^}]*)\}' -AllMatches |
        ForEach-Object { $_.Matches } |
        ForEach-Object { $_.Groups[1].Value } |
        Where-Object { $_ -notmatch '^(Snapshot|Capture|Attached|Inject)' } |
        ForEach-Object { $_ -replace '^\[\d+\]\s*', '' }
}

$interfaces = @(Get-UsbPcapInterfaces)
if (-not $interfaces) { Fail "USBPcapCMD lists no USBPcap interfaces. Is the USBPcap driver installed (reboot after install)?" }

$usbBase = ($usbDev.FriendlyName -replace '\s*\(COM\d+\)\s*$', '').Trim()

$target = $null
if ($Interface) {
    if ($Interface -notlike '\\.\*') { $Interface = "\\.\$Interface" }
    $target = $Interface
}
else {
    foreach ($iface in $interfaces) {
        $names = @(Get-TreeNames (Get-UsbPcapTree $iface))
        if (-not $names) { continue }
        if ($Port -and ($names | Where-Object { $_ -match "\($Port\)$" })) { $target = $iface; break }
        if ($names | Where-Object { ($_ -replace '\s*\(COM\d+\)\s*$', '').Trim() -eq $usbBase }) { $target = $iface; break }
    }
}

if (-not $target) {
    Write-Host ""
    Write-Host "Could not match '$($usbDev.FriendlyName)' to a USBPcap interface." -ForegroundColor Yellow
    Write-Host "Device trees currently visible to USBPcap:"
    foreach ($iface in $interfaces) {
        $names = @(Get-TreeNames (Get-UsbPcapTree $iface))
        if ($names) { Write-Host "  $iface : $($names -join ', ')" }
    }
    Fail "Pick the interface from the list and pass it as -Interface, or replug the device and retry."
}

Write-Host "Interface: $target" -ForegroundColor Green

# --- Wireshark preferences can silently disable the capture -------------------
# tshark hands USBPcapCMD the extcap options saved in Wireshark's preferences
# file, keyed by a sanitised interface name (\\.\USBPcap1 -> ____usbpcap1). If
# "capture from all devices" is saved as false and no device list is saved,
# USBPcapCMD captures from nothing and the file stays empty. Override per run
# with -o; the value must be lowercase "true", tshark ignores "TRUE".

$prefKey = ($target.ToLower() -replace '[^a-z0-9]', '_')
$prefFile = Join-Path $env:APPDATA "Wireshark\preferences"
if (Test-Path $prefFile) {
    $badPrefs = @(Select-String -Path $prefFile `
        -Pattern "^\s*extcap\.$prefKey\.(capturefromalldevices|capturefromnewdevices|injectdescriptors):\s*false" |
        ForEach-Object { $_.Line.Trim() })
    if ($badPrefs) {
        Write-Host ""
        Warn "Wireshark's saved preferences disable capture options on $target :"
        foreach ($line in $badPrefs) { Write-Host "    $line" -ForegroundColor Yellow }
        Write-Host "  This script overrides them for its own run. Captures made directly with" -ForegroundColor Yellow
        Write-Host "  Wireshark or tshark on this interface will be EMPTY until you re-tick" -ForegroundColor Yellow
        Write-Host "  'Capture from all devices' and 'Inject already connected devices descriptors'" -ForegroundColor Yellow
        Write-Host "  in the interface's options dialog, or delete those lines from" -ForegroundColor Yellow
        Write-Host "  $prefFile" -ForegroundColor Yellow
    }
}

# --- capture -----------------------------------------------------------------

if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$safeTag = ($Tag -replace '[^\w\-]', '-')
$outBase = "usb-$safeTag-$stamp"
$out = Join-Path (Resolve-Path $OutDir) "$outBase.pcapng"

$tsharkArgs = @(
    "-o", "extcap.$prefKey.capturefromalldevices:true",
    "-o", "extcap.$prefKey.capturefromnewdevices:true",
    "-o", "extcap.$prefKey.injectdescriptors:true",
    "-i", $target,
    "-w", $out
)
if ($Seconds -gt 0) { $tsharkArgs += @("-a", "duration:$Seconds") }
if ($RingMinutes -gt 0) {
    $tsharkArgs += @("-b", "duration:$($RingMinutes * 60)", "-b", "files:$RingFiles")
}

Write-Host ""
Write-Host "Writing to $out" -ForegroundColor Cyan
if ($RingMinutes -gt 0) {
    $total = $RingMinutes * $RingFiles
    Write-Host ("Ring buffer: {0} files x {1} min = {2} min ({3:N1} h) of rolling history." `
                -f $RingFiles, $RingMinutes, $total, ($total / 60)) -ForegroundColor Cyan
    Write-Host "Oldest files are recycled, so disk use stays bounded." -ForegroundColor Cyan
}
if ($Seconds -gt 0) {
    Write-Host "Capturing for $Seconds seconds..." -ForegroundColor Cyan
} else {
    Write-Host "Capturing until you press Ctrl-C..." -ForegroundColor Cyan
}
Write-Host ""

# Ctrl-C normally kills this script along with tshark, so the checks below
# would never run. Start tshark first (it inherits the console as-is), then
# tell Windows to stop delivering Ctrl-C to this process only: tshark still
# gets it, stops cleanly, flushes the file, and we carry on to inspect it.
Add-Type -Namespace Pcaper -Name ConsoleCtrl -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);
'@

# Not Start-Process -NoNewWindow: that puts the child on a hidden console of
# its own, where the terminal's Ctrl-C never arrives and the capture cannot be
# stopped. Process.Start with UseShellExecute off shares this console.
function Quote-Arg([string]$a) {
    if ($a -match '[\s"]') { '"' + ($a -replace '"', '\"') + '"' } else { $a }
}
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $tshark
$psi.Arguments = ($tsharkArgs | ForEach-Object { Quote-Arg $_ }) -join ' '
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $false
# The "ignore Ctrl-C" flag is inherited at process creation. Clear any we
# inherited ourselves first, so tshark starts able to see Ctrl-C even when
# this script was launched from a host that ignores it (task runners, agents).
[Pcaper.ConsoleCtrl]::SetConsoleCtrlHandler([IntPtr]::Zero, $false) | Out-Null
$proc = [System.Diagnostics.Process]::Start($psi)
[Pcaper.ConsoleCtrl]::SetConsoleCtrlHandler([IntPtr]::Zero, $true) | Out-Null
try {
    # The extcap takes a moment to come up; invite the user to act only once it
    # is likely live, or the port open lands before the capture starts.
    if (-not $proc.WaitForExit(3000)) {
        Write-Host ""
        Write-Host "Capture running." -ForegroundColor Cyan
        if ($Port) { Write-Host "Now open $Port in the application. The open sequence is worth capturing." -ForegroundColor Cyan }
        Write-Host ""
    }
    $proc.WaitForExit()
} finally {
    [Pcaper.ConsoleCtrl]::SetConsoleCtrlHandler([IntPtr]::Zero, $false) | Out-Null
}
Write-Host ""

# --- did we actually get anything? -------------------------------------------

function Count-Frames([string]$file, [string]$filter) {
    $lines = & $tshark -r $file -Y $filter -T fields -e frame.number 2>$null | Measure-Object -Line
    return [int]$lines.Lines
}

function Test-Capture([string]$file) {
    $packets = 0
    if (Test-Path $capinfos) {
        $info = & $capinfos -c -M $file 2>$null | Select-String 'Number of packets:\s*(\d+)'
        if ($info) { $packets = [int]$info.Matches[0].Groups[1].Value }
    } else {
        $packets = Count-Frames $file 'frame'
    }

    if ($packets -eq 0) {
        Write-Host "VERDICT: EMPTY. USBPcap recorded nothing on $target, not even device descriptors." -ForegroundColor Red
        Write-Host "  That is the capture failing to start, not a quiet device. Check the" -ForegroundColor Red
        Write-Host "  preferences warning above, run from an elevated shell, and make sure no" -ForegroundColor Red
        Write-Host "  other capture (Wireshark, another tshark) holds $target." -ForegroundColor Red
        return $false
    }

    $addrs = @(& $tshark -r $file -Y "usb.idVendor == 0x$vid && usb.idProduct == 0x$pid_" `
                 -T fields -e usb.device_address 2>$null | Sort-Object -Unique)
    if (-not $addrs) {
        Write-Host "VERDICT: $packets packets, but none from VID:PID $VidPid." -ForegroundColor Red
        Write-Host "  Either the device is on a different root hub than $target, or its" -ForegroundColor Red
        Write-Host "  descriptors were not injected, so the analysis tools cannot find it." -ForegroundColor Red
        return $false
    }
    $addr = $addrs[-1]   # a replug reassigns the address; the latest one is live
    $devFilter = "usb.device_address == $addr"
    $devFrames = Count-Frames $file $devFilter
    $dataFrames = Count-Frames $file "$devFilter && (usb.transfer_type == 0x03 || usb.transfer_type == 0x01)"
    $payloadFrames = Count-Frames $file ("$devFilter && (usbcom.data.in_payload || usbcom.data.out_payload || " +
        "ftdi-ft.if_a_rx_payload || ftdi-ft.if_a_tx_payload || ftdi-ft.if_b_rx_payload || ftdi-ft.if_b_tx_payload || usb.capdata)")

    Write-Host ("Device address {0}: {1} frames, {2} bulk/interrupt transfers, {3} carrying serial bytes (of {4} total packets)" `
                -f $addr, $devFrames, $dataFrames, $payloadFrames, $packets)
    if ($dataFrames -eq 0) {
        Write-Host "VERDICT: device seen, port never opened. Only descriptors/control traffic." -ForegroundColor Yellow
        Write-Host "  Nothing opened the port while the capture ran. Start the capture first," -ForegroundColor Yellow
        Write-Host "  then open the port in the application." -ForegroundColor Yellow
        return $false
    }
    if ($payloadFrames -eq 0) {
        Write-Host "VERDICT: port was opened but no serial bytes flowed in either direction." -ForegroundColor Yellow
        Write-Host "  (For FTDI adapters the driver polls the chip continuously; those status-only" -ForegroundColor Yellow
        Write-Host "  reads are not counted as data.)" -ForegroundColor Yellow
        return $false
    }
    Write-Host "VERDICT: OK. Serial traffic for $VidPid is in the capture." -ForegroundColor Green
    return $true
}

# With a ring buffer tshark names files <base>_NNNNN_<timestamp>.pcapng; check
# the newest one, which is the one holding whatever just happened.
$files = @()
if (Test-Path $out) { $files = @(Get-Item $out) }
elseif ($RingMinutes -gt 0) {
    $files = @(Get-ChildItem -Path (Split-Path $out) -Filter "${outBase}_*.pcapng" | Sort-Object LastWriteTime)
}

if (-not $files) {
    Write-Host "No capture file was written (tshark exit code $($proc.ExitCode))." -ForegroundColor Red
    Write-Host "  'Couldn't open device - 5' above means another capture already holds $target" -ForegroundColor Red
    Write-Host "  (Wireshark, or a stray tshark/USBPcapCMD from an earlier run). Stop it and retry." -ForegroundColor Red
    exit 1
}

$latest = $files[-1]
$size = [math]::Round($latest.Length / 1KB, 1)
if ($files.Count -gt 1) { Write-Host "Saved $($files.Count) ring files; newest $($latest.FullName) ($size KB)" -ForegroundColor Green }
else { Write-Host "Saved $($latest.FullName) ($size KB)" -ForegroundColor Green }

$ok = Test-Capture $latest.FullName

Write-Host ""
Write-Host "Next:" -ForegroundColor Cyan
Write-Host "  py urbtrace.py `"$($latest.FullName)`" --vidpid $VidPid"
Write-Host "  py pcaper.py `"$($latest.FullName)`" -f gcode"
if (-not $ok) { exit 2 }
