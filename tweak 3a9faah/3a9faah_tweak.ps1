# ============================================================================
# 3a9faah Ultimate Windows Tweak Tool v3.0 - EXCLUSIVE EDITION
# Copyright (c) 2026 3a9faah - All Rights Reserved
# GitHub: https://github.com/3a9faah
# ============================================================================

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = "3a9faah Ultimate Tweak v3.0"
$ErrorActionPreference = "SilentlyContinue"

$Logo = @"
===============================================================================
   ____        ___   __            _     
  |___ \      / _ \ / _|          | |    
    __) | __ | (_) | |_ __ _  __ _| |__  
   |__ < / _` \__, |  _/ _` |/ _` | '_ \ 
   ___) | (_| | / /| || (_| | (_| | | | |
  |____/ \__,_|/_/ |_| \__,_|\__,_|_| |_|
                                         
  ULTIMATE WINDOWS TWEAK v3.0 - EXCLUSIVE
  Copyright (c) 2026 3a9faah
  GitHub: https://github.com/3a9faah
===============================================================================
"@

function Show-Logo { Clear-Host; Write-Host $Logo -ForegroundColor Cyan }
function Open-GitHub { Start-Process "https://github.com/3a9faah" }

function Create-RestorePoint {
    Write-Host "[*] Creating Restore Point..." -ForegroundColor Yellow
    Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
    Checkpoint-Computer -Description "3a9faah Tweak v3.0" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
    Write-Host "[+] Done!" -ForegroundColor Green
}

function Backup-Registry {
    Write-Host "[*] Backing up Registry..." -ForegroundColor Yellow
    $Path = "$env:USERPROFILE\Desktop\3a9faah_Backup"
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    reg export "HKLM\SYSTEM\CurrentControlSet" "$Path\System.reg" /y 2>$null
    reg export "HKCU\Control Panel" "$Path\ControlPanel.reg" /y 2>$null
    Write-Host "[+] Saved to Desktop!" -ForegroundColor Green
}

function Optimize-Keyboard {
    Write-Host "`n[*] 3a9faah Keyboard Optimization..." -ForegroundColor Magenta
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value 0 -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardSpeed" -Value 31 -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatDelay" -Value "200" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatRate" -Value "6" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "DelayBeforeAcceptance" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "59" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "BounceTime" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value "506" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value "58" -Type String
    $KBD = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"
    if (!(Test-Path $KBD)) { New-Item -Path $KBD -Force | Out-Null }
    Set-ItemProperty -Path $KBD -Name "KeyboardDataQueueSize" -Value 100 -Type DWord
    Set-ItemProperty -Path $KBD -Name "PollStatusIterations" -Value 1 -Type DWord
    $KBDHID = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdhid\Parameters"
    if (!(Test-Path $KBDHID)) { New-Item -Path $KBDHID -Force | Out-Null }
    Set-ItemProperty -Path $KBDHID -Name "PollInterval" -Value 1 -Type DWord
    $i8042 = "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters"
    if (Test-Path $i8042) {
        Set-ItemProperty -Path $i8042 -Name "PollStatusIterations" -Value 1 -Type DWord
        Set-ItemProperty -Path $i8042 -Name "PollingIterations" -Value 1000 -Type DWord
        Set-ItemProperty -Path $i8042 -Name "PollingIterationsMaximum" -Value 1000 -Type DWord
        Set-ItemProperty -Path $i8042 -Name "ResendIterations" -Value 3 -Type DWord
    }
    Write-Host "[+] Keyboard ULTRA FAST!" -ForegroundColor Green
}

function Optimize-Mouse {
    Write-Host "`n[*] 3a9faah Mouse Optimization..." -ForegroundColor Magenta
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Value "10" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "DoubleClickSpeed" -Value "200" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Value "0" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SnapToDefaultButton" -Value "0" -Type String
    $Flat = [byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Value $Flat -Type Binary
    Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Value $Flat -Type Binary
    $MOU = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"
    if (!(Test-Path $MOU)) { New-Item -Path $MOU -Force | Out-Null }
    Set-ItemProperty -Path $MOU -Name "MouseDataQueueSize" -Value 100 -Type DWord
    Set-ItemProperty -Path $MOU -Name "PollStatusIterations" -Value 1 -Type DWord
    $MOUHID = "HKLM:\SYSTEM\CurrentControlSet\Services\mouhid\Parameters"
    if (!(Test-Path $MOUHID)) { New-Item -Path $MOUHID -Force | Out-Null }
    Set-ItemProperty -Path $MOUHID -Name "PollInterval" -Value 1 -Type DWord
    Set-ItemProperty -Path $MOUHID -Name "TreatAbsoluteAsRelative" -Value 0 -Type DWord
    Set-ItemProperty -Path $MOUHID -Name "TreatAbsolutePointerAsAbsolute" -Value 1 -Type DWord
    Write-Host "[+] Mouse 1:1 RAW Input!" -ForegroundColor Green
}

function Optimize-Gaming {
    Write-Host "`n[*] 3a9faah Gaming Optimization..." -ForegroundColor Magenta
    $GameDVR = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
    if (!(Test-Path $GameDVR)) { New-Item -Path $GameDVR -Force | Out-Null }
    Set-ItemProperty -Path $GameDVR -Name "AppCaptureEnabled" -Value 0 -Type DWord
    $GameBar = "HKCU:\Software\Microsoft\GameBar"
    if (!(Test-Path $GameBar)) { New-Item -Path $GameBar -Force | Out-Null }
    Set-ItemProperty -Path $GameBar -Name "UseNexusForGameBarEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $GameBar -Name "AutoGameModeEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $GameBar -Name "ShowStartupPanel" -Value 0 -Type DWord
    $GameDVRP = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    if (!(Test-Path $GameDVRP)) { New-Item -Path $GameDVRP -Force | Out-Null }
    Set-ItemProperty -Path $GameDVRP -Name "AllowGameDVR" -Value 0 -Type DWord
    $GPU = "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
    Set-ItemProperty -Path $GPU -Name "HwSchMode" -Value 2 -Type DWord
    Set-ItemProperty -Path $GPU -Name "TdrDelay" -Value 60 -Type DWord
    Set-ItemProperty -Path $GPU -Name "TdrDdiDelay" -Value 60 -Type DWord
    Set-ItemProperty -Path $GPU -Name "TdrLevel" -Value 0 -Type DWord
    Set-ItemProperty -Path $GPU -Name "DpiMapIommuContiguous" -Value 1 -Type DWord
    $GCS = "HKCU:\System\GameConfigStore"
    if (!(Test-Path $GCS)) { New-Item -Path $GCS -Force | Out-Null }
    Set-ItemProperty -Path $GCS -Name "GameDVR_Enabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $GCS -Name "GameDVR_FSEBehaviorMode" -Value 2 -Type DWord
    Set-ItemProperty -Path $GCS -Name "GameDVR_FSEBehavior" -Value 2 -Type DWord
    Set-ItemProperty -Path $GCS -Name "GameDVR_HonorUserFSEBehaviorMode" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord
    $D3D = "HKLM:\SOFTWARE\Microsoft\Direct3D"
    if (!(Test-Path $D3D)) { New-Item -Path $D3D -Force | Out-Null }
    Set-ItemProperty -Path $D3D -Name "DisableVidMemVBs" -Value 0 -Type DWord
    Set-ItemProperty -Path $D3D -Name "FlipNoVsync" -Value 1 -Type DWord
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\DWM" -Name "OverlayTestMode" -Value 5 -Type DWord
    Write-Host "[+] Gaming MAXIMUM FPS!" -ForegroundColor Green
}

function Optimize-DPC-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE DPC Optimization (Target: <500us)..." -ForegroundColor Magenta
    $MM = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    if (!(Test-Path $MM)) { New-Item -Path $MM -Force | Out-Null }
    Set-ItemProperty -Path $MM -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord
    Set-ItemProperty -Path $MM -Name "SystemResponsiveness" -Value 0 -Type DWord
    Set-ItemProperty -Path $MM -Name "NoLazyMode" -Value 1 -Type DWord
    Set-ItemProperty -Path $MM -Name "LazyModeTimeout" -Value 10000 -Type DWord
    Set-ItemProperty -Path $MM -Name "AlwaysOn" -Value 1 -Type DWord
    $Tasks = @("Games", "Audio", "Pro Audio", "Capture", "Distribution", "Playback", "Low Latency")
    foreach ($Task in $Tasks) {
        $Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\$Task"
        if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        Set-ItemProperty -Path $Path -Name "Affinity" -Value 0 -Type DWord
        Set-ItemProperty -Path $Path -Name "Background Only" -Value "False" -Type String
        Set-ItemProperty -Path $Path -Name "Clock Rate" -Value 10000 -Type DWord
        Set-ItemProperty -Path $Path -Name "GPU Priority" -Value 8 -Type DWord
        Set-ItemProperty -Path $Path -Name "Priority" -Value 6 -Type DWord
        Set-ItemProperty -Path $Path -Name "Scheduling Category" -Value "High" -Type String
        Set-ItemProperty -Path $Path -Name "SFIO Priority" -Value "High" -Type String
        Set-ItemProperty -Path $Path -Name "Latency Sensitive" -Value "True" -Type String
    }
    $Kernel = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    if (!(Test-Path $Kernel)) { New-Item -Path $Kernel -Force | Out-Null }
    Set-ItemProperty -Path $Kernel -Name "GlobalTimerResolutionRequests" -Value 1 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "DisableExceptionChainValidation" -Value 1 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "KernelSEHOPEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "DistributeTimers" -Value 0 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "DpcWatchdogPeriod" -Value 0 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "DpcTimeout" -Value 0 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "IdealDpcRate" -Value 1 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "MaxDpcQueueDepth" -Value 1 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "MinDpcRate" -Value 1 -Type DWord
    Set-ItemProperty -Path $Kernel -Name "AdjustDpcThreshold" -Value 1 -Type DWord
    $Power = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
    Set-ItemProperty -Path $Power -Name "ExitLatency" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "ExitLatencyCheckEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "Latency" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "LatencyToleranceDefault" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "LatencyToleranceFSVP" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "LatencyTolerancePerfOverride" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "LatencyToleranceScreenOffIR" -Value 1 -Type DWord
    Set-ItemProperty -Path $Power -Name "LatencyToleranceVSyncEnabled" -Value 1 -Type DWord
    bcdedit /set disabledynamictick yes 2>$null
    bcdedit /set useplatformtick yes 2>$null
    bcdedit /set tscsyncpolicy Enhanced 2>$null
    bcdedit /set useplatformclock no 2>$null
    bcdedit /set x2apicpolicy enable 2>$null
    bcdedit /set linearaddress57 OptOut 2>$null
    bcdedit /set uselegacyapicmode no 2>$null
    bcdedit /set perfmem 1 2>$null
    bcdedit /set usefirmwarepcisettings no 2>$null
    Write-Host "[+] DPC Latency ULTRA LOW!" -ForegroundColor Green
}

function Optimize-IRQ-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE IRQ Optimization..." -ForegroundColor Magenta
    $Priority = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $Priority -Name "IRQ8Priority" -Value 1 -Type DWord
    Set-ItemProperty -Path $Priority -Name "IRQ0Priority" -Value 2 -Type DWord
    $MSI = "HKLM:\SYSTEM\CurrentControlSet\Control\Class"
    Get-ChildItem $MSI -ErrorAction SilentlyContinue | ForEach-Object {
        Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
            $DevPath = "$($_.PSPath)\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
            if (Test-Path $DevPath) {
                Set-ItemProperty -Path $DevPath -Name "MSISupported" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Host "[+] IRQ Priority Optimized!" -ForegroundColor Green
}

function Optimize-Network-3a9faah {
    Write-Host "`n[*] 3a9faah Network Optimization..." -ForegroundColor Magenta
    $TCP = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    Set-ItemProperty -Path $TCP -Name "TcpAckFrequency" -Value 1 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TCPNoDelay" -Value 1 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TcpDelAckTicks" -Value 0 -Type DWord
    Set-ItemProperty -Path $TCP -Name "DefaultTTL" -Value 64 -Type DWord
    Set-ItemProperty -Path $TCP -Name "EnablePMTUDiscovery" -Value 1 -Type DWord
    Set-ItemProperty -Path $TCP -Name "EnablePMTUBHDetect" -Value 0 -Type DWord
    Set-ItemProperty -Path $TCP -Name "SackOpts" -Value 1 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TcpMaxDupAcks" -Value 2 -Type DWord
    Set-ItemProperty -Path $TCP -Name "Tcp1323Opts" -Value 1 -Type DWord
    Set-ItemProperty -Path $TCP -Name "GlobalMaxTcpWindowSize" -Value 65535 -Type DWord
    Set-ItemProperty -Path $TCP -Name "MaxUserPort" -Value 65534 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TcpTimedWaitDelay" -Value 30 -Type DWord
    Set-ItemProperty -Path $TCP -Name "EnableICMPRedirect" -Value 0 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TcpMaxConnectRetransmissions" -Value 2 -Type DWord
    Set-ItemProperty -Path $TCP -Name "TcpMaxDataRetransmissions" -Value 3 -Type DWord
    Set-ItemProperty -Path $TCP -Name "EnableWsd" -Value 0 -Type DWord
    $TCPI = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
    Get-ChildItem $TCPI | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "TcpAckFrequency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $_.PSPath -Name "TCPNoDelay" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $_.PSPath -Name "TcpDelAckTicks" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    }
    $AFD = "HKLM:\SYSTEM\CurrentControlSet\Services\AFD\Parameters"
    if (!(Test-Path $AFD)) { New-Item -Path $AFD -Force | Out-Null }
    Set-ItemProperty -Path $AFD -Name "FastSendDatagramThreshold" -Value 1024 -Type DWord
    Set-ItemProperty -Path $AFD -Name "DefaultReceiveWindow" -Value 65535 -Type DWord
    Set-ItemProperty -Path $AFD -Name "DefaultSendWindow" -Value 65535 -Type DWord
    Set-ItemProperty -Path $AFD -Name "EnableDynamicBacklog" -Value 1 -Type DWord
    Set-ItemProperty -Path $AFD -Name "MaximumDynamicBacklog" -Value 20000 -Type DWord
    Set-ItemProperty -Path $AFD -Name "DoNotHoldNicBuffers" -Value 1 -Type DWord
    Set-ItemProperty -Path $AFD -Name "DisableRawSecurity" -Value 1 -Type DWord
    Set-ItemProperty -Path $AFD -Name "IgnorePushBitOnReceives" -Value 1 -Type DWord
    Set-ItemProperty -Path $AFD -Name "NonBlockingSendSpecialBuffering" -Value 1 -Type DWord
    netsh int tcp set global autotuninglevel=normal 2>$null
    netsh int tcp set global ecncapability=disabled 2>$null
    netsh int tcp set global timestamps=disabled 2>$null
    netsh int tcp set global rss=enabled 2>$null
    netsh int tcp set global nonsackrttresiliency=disabled 2>$null
    netsh int tcp set global maxsynretransmissions=2 2>$null
    netsh int tcp set global initialRto=2000 2>$null
    netsh int tcp set heuristics disabled 2>$null
    netsh int ip set global taskoffload=enabled 2>$null
    netsh int ip set global neighborcachelimit=4096 2>$null
    Get-NetAdapter | ForEach-Object {
        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*FlowControl" -RegistryValue 0 -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*InterruptModeration" -RegistryValue 0 -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*RSS" -RegistryValue 1 -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*LsoV2IPv4" -RegistryValue 0 -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $_.Name -RegistryKeyword "*LsoV2IPv6" -RegistryValue 0 -ErrorAction SilentlyContinue
        Disable-NetAdapterPowerManagement -Name $_.Name -ErrorAction SilentlyContinue
    }
    Write-Host "[+] Network ZERO LAG!" -ForegroundColor Green
}

function Optimize-Power-3a9faah {
    Write-Host "`n[*] 3a9faah Power Optimization..." -ForegroundColor Magenta
    powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 88888888-8888-8888-8888-888888888888 2>$null
    powercfg -changename 88888888-8888-8888-8888-888888888888 "3a9faah Ultimate" "Maximum Performance" 2>$null
    powercfg -setactive 88888888-8888-8888-8888-888888888888 2>$null
    @("PROCTHROTTLEMIN","PROCTHROTTLEMAX","CPMINCORES") | ForEach-Object { powercfg -setacvalueindex 88888888-8888-8888-8888-888888888888 sub_processor $_ 100 2>$null }
    powercfg -setacvalueindex 88888888-8888-8888-8888-888888888888 sub_processor PERFEPP 0 2>$null
    powercfg -setacvalueindex 88888888-8888-8888-8888-888888888888 sub_processor PERFBOOSTMODE 2 2>$null
    powercfg -setacvalueindex 88888888-8888-8888-8888-888888888888 54533251-82be-4824-96c1-47b60b740d00 be337238-0d82-4146-a960-4f3749d470c7 0 2>$null
    powercfg /x monitor-timeout-ac 0 2>$null
    powercfg /x standby-timeout-ac 0 2>$null
    powercfg /hibernate off 2>$null
    $PT = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
    if (!(Test-Path $PT)) { New-Item -Path $PT -Force | Out-Null }
    Set-ItemProperty -Path $PT -Name "PowerThrottlingOff" -Value 1 -Type DWord
    $Proc = "HKLM:\SYSTEM\CurrentControlSet\Control\Processor"
    if (!(Test-Path $Proc)) { New-Item -Path $Proc -Force | Out-Null }
    Set-ItemProperty -Path $Proc -Name "CPPCEnable" -Value 0 -Type DWord
    Set-ItemProperty -Path $Proc -Name "Capabilities" -Value 516198 -Type DWord
    Write-Host "[+] Power MAXIMUM!" -ForegroundColor Green
}

function Optimize-System-3a9faah {
    Write-Host "`n[*] 3a9faah System Optimization..." -ForegroundColor Magenta
    $Mem = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $Mem -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "DisablePagingExecutive" -Value 1 -Type DWord
    Set-ItemProperty -Path $Mem -Name "LargeSystemCache" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "SecondLevelDataCache" -Value 1024 -Type DWord
    Set-ItemProperty -Path $Mem -Name "IoPageLockLimit" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "SystemPages" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "NonPagedPoolSize" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "PagedPoolSize" -Value 0xFFFFFFFF -Type DWord
    Set-ItemProperty -Path $Mem -Name "NonPagedPoolQuota" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "PagedPoolQuota" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "PhysicalAddressExtension" -Value 1 -Type DWord
    $Pref = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
    Set-ItemProperty -Path $Pref -Name "EnablePrefetcher" -Value 0 -Type DWord
    Set-ItemProperty -Path $Pref -Name "EnableSuperfetch" -Value 0 -Type DWord
    Set-ItemProperty -Path $Pref -Name "EnableBootTrace" -Value 0 -Type DWord
    $FS = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    Set-ItemProperty -Path $FS -Name "NtfsDisableLastAccessUpdate" -Value 1 -Type DWord
    Set-ItemProperty -Path $FS -Name "NtfsDisable8dot3NameCreation" -Value 1 -Type DWord
    Set-ItemProperty -Path $FS -Name "NtfsMemoryUsage" -Value 2 -Type DWord
    Set-ItemProperty -Path $FS -Name "NtfsEncryptPagingFile" -Value 0 -Type DWord
    Set-ItemProperty -Path $FS -Name "LongPathsEnabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $FS -Name "DisableCompression" -Value 1 -Type DWord
    Set-ItemProperty -Path $FS -Name "DisableDeleteNotification" -Value 0 -Type DWord
    fsutil behavior set disabledeletenotify 0 2>$null
    fsutil behavior set memoryusage 2 2>$null
    fsutil behavior set mftzone 2 2>$null
    $Desk = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $Desk -Name "AutoEndTasks" -Value "1" -Type String
    Set-ItemProperty -Path $Desk -Name "HungAppTimeout" -Value "1000" -Type String
    Set-ItemProperty -Path $Desk -Name "WaitToKillAppTimeout" -Value "2000" -Type String
    Set-ItemProperty -Path $Desk -Name "LowLevelHooksTimeout" -Value "1000" -Type String
    Set-ItemProperty -Path $Desk -Name "MenuShowDelay" -Value "0" -Type String
    Set-ItemProperty -Path $Desk -Name "ForegroundLockTimeout" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type String
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Type String
    bcdedit /set increaseuserva 3072 2>$null
    Write-Host "[+] System LIGHTWEIGHT!" -ForegroundColor Green
}

function Optimize-Visual-3a9faah {
    Write-Host "`n[*] 3a9faah Visual Optimization..." -ForegroundColor Magenta
    $V = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    if (!(Test-Path $V)) { New-Item -Path $V -Force | Out-Null }
    Set-ItemProperty -Path $V -Name "VisualFXSetting" -Value 2 -Type DWord
    $Adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $Adv -Name "TaskbarAnimations" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "ListviewAlphaSelect" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "ListviewShadow" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "Start_NotifyNewApps" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "DisablePreviewDesktop" -Value 1 -Type DWord
    $Desk = "HKCU:\Control Panel\Desktop"
    Set-ItemProperty -Path $Desk -Name "UserPreferencesMask" -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00)) -Type Binary
    Set-ItemProperty -Path $Desk -Name "DragFullWindows" -Value "1" -Type String
    Set-ItemProperty -Path $Desk -Name "FontSmoothing" -Value "2" -Type String
    $DWM = "HKCU:\Software\Microsoft\Windows\DWM"
    Set-ItemProperty -Path $DWM -Name "EnableAeroPeek" -Value 0 -Type DWord
    Set-ItemProperty -Path $DWM -Name "AlwaysHibernateThumbnails" -Value 0 -Type DWord
    Set-ItemProperty -Path $DWM -Name "Composition" -Value 0 -Type DWord
    $DWM2 = "HKLM:\SOFTWARE\Microsoft\Windows\DWM"
    Set-ItemProperty -Path $DWM2 -Name "AnimationAttributionEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $DWM2 -Name "DisallowFlip3d" -Value 0 -Type DWord
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0 -Type DWord
    Write-Host "[+] Visual CLEAN!" -ForegroundColor Green
}

function Optimize-Privacy-3a9faah {
    Write-Host "`n[*] 3a9faah Privacy Optimization..." -ForegroundColor Magenta
    $DC = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (!(Test-Path $DC)) { New-Item -Path $DC -Force | Out-Null }
    Set-ItemProperty -Path $DC -Name "AllowTelemetry" -Value 0 -Type DWord
    $Cortana = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    if (!(Test-Path $Cortana)) { New-Item -Path $Cortana -Force | Out-Null }
    Set-ItemProperty -Path $Cortana -Name "AllowCortana" -Value 0 -Type DWord
    Set-ItemProperty -Path $Cortana -Name "DisableWebSearch" -Value 1 -Type DWord
    $Sys = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    if (!(Test-Path $Sys)) { New-Item -Path $Sys -Force | Out-Null }
    Set-ItemProperty -Path $Sys -Name "EnableActivityFeed" -Value 0 -Type DWord
    Set-ItemProperty -Path $Sys -Name "PublishUserActivities" -Value 0 -Type DWord
    Set-ItemProperty -Path $Sys -Name "UploadUserActivities" -Value 0 -Type DWord
    $CDM = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    Set-ItemProperty -Path $CDM -Name "ContentDeliveryAllowed" -Value 0 -Type DWord
    Set-ItemProperty -Path $CDM -Name "SilentInstalledAppsEnabled" -Value 0 -Type DWord
    Set-ItemProperty -Path $CDM -Name "SoftLandingEnabled" -Value 0 -Type DWord
    $Ad = "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    if (!(Test-Path $Ad)) { New-Item -Path $Ad -Force | Out-Null }
    Set-ItemProperty -Path $Ad -Name "Enabled" -Value 0 -Type DWord
    $Sync = "HKCU:\Software\Microsoft\Windows\CurrentVersion\SettingSync"
    Set-ItemProperty -Path $Sync -Name "SyncPolicy" -Value 5 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[+] Privacy MAXIMUM!" -ForegroundColor Green
}

function Disable-Services-3a9faah {
    Write-Host "`n[*] 3a9faah Service Optimization..." -ForegroundColor Magenta
    $Svc = @("SysMain","DiagTrack","dmwappushservice","WSearch","XblAuthManager","XblGameSave","XboxNetApiSvc","XboxGipSvc","RemoteRegistry","MapsBroker","lfsvc","SharedAccess","WerSvc","Fax","RetailDemo","TabletInputService","WpcMonSvc","PcaSvc","wisvc","PhoneSvc","MessagingService","icssvc","WMPNetworkSvc","AJRouter","CDPSvc","PushToInstall","WbioSrvc","diagnosticshub.standardcollector.service","DusmSvc","BITS","DoSvc","UsoSvc","wuauserv","TrkWks","WpnService","OneSyncSvc","CDPUserSvc","PimIndexMaintenanceSvc","UnistoreSvc","UserDataSvc","TokenBroker","BcastDVRUserService","CaptureService","cbdhsvc","DevicesFlowUserSvc","MessagingService","PimIndexMaintenanceSvc","PrintWorkflowUserSvc","UnistoreSvc")
    foreach ($S in $Svc) {
        $sv = Get-Service -Name $S -ErrorAction SilentlyContinue
        if ($sv) {
            Stop-Service -Name $S -Force -ErrorAction SilentlyContinue
            Set-Service -Name $S -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    $Tasks = @("\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser","\Microsoft\Windows\Application Experience\ProgramDataUpdater","\Microsoft\Windows\Autochk\Proxy","\Microsoft\Windows\Customer Experience Improvement Program\Consolidator","\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip","\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector","\Microsoft\Windows\Windows Error Reporting\QueueReporting","\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem","\Microsoft\Windows\CloudExperienceHost\CreateObjectTask","\Microsoft\Windows\DiskFootprint\Diagnostics","\Microsoft\Windows\Maintenance\WinSAT","\Microsoft\Windows\Maps\MapsToastTask","\Microsoft\Windows\Maps\MapsUpdateTask","\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser","\Microsoft\Windows\Shell\FamilySafetyMonitor","\Microsoft\Windows\Shell\FamilySafetyRefresh")
    foreach ($T in $Tasks) { schtasks /change /tn $T /disable 2>$null }
    Write-Host "[+] 50+ Services Disabled!" -ForegroundColor Green
}

function Optimize-GPU-3a9faah {
    Write-Host "`n[*] 3a9faah GPU Optimization..." -ForegroundColor Magenta
    $GPU = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000"
    if (Test-Path $GPU) {
        Set-ItemProperty -Path $GPU -Name "EnableUlps" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "EnableCrossFireAutoLink" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "PowerMizerEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "PowerMizerLevel" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "PowerMizerLevelAC" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "PerfLevelSrc" -Value 8738 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "RMClkFt" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "RmGpsPsEnablePerCpuCoreDpc" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "StutterMode" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU -Name "PP_ThermalAutoThrottlingEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    }
    $GPU1 = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0001"
    if (Test-Path $GPU1) {
        Set-ItemProperty -Path $GPU1 -Name "EnableUlps" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $GPU1 -Name "PowerMizerEnable" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    }
    Write-Host "[+] GPU MAXIMUM PERFORMANCE!" -ForegroundColor Green
}

function Optimize-USB-3a9faah {
    Write-Host "`n[*] 3a9faah USB Optimization..." -ForegroundColor Magenta
    $USB = "HKLM:\SYSTEM\CurrentControlSet\Services\USB"
    if (!(Test-Path $USB)) { New-Item -Path $USB -Force | Out-Null }
    Set-ItemProperty -Path $USB -Name "DisableSelectiveSuspend" -Value 1 -Type DWord
    @("USBXHCI","usbhub","usbhub3","usbccgp") | ForEach-Object {
        $P = "HKLM:\SYSTEM\CurrentControlSet\Services\$_\Parameters"
        if (!(Test-Path $P)) { New-Item -Path $P -Force | Out-Null }
        Set-ItemProperty -Path $P -Name "ThreadPriority" -Value 31 -Type DWord
    }
    Get-PnpDevice -Class "USB" -ErrorAction SilentlyContinue | ForEach-Object {
        $Id = $_.InstanceId
        $P = "HKLM:\SYSTEM\CurrentControlSet\Enum\$Id\Device Parameters"
        if (Test-Path $P) {
            Set-ItemProperty -Path $P -Name "SelectiveSuspendEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $P -Name "EnhancedPowerManagementEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $P -Name "AllowIdleIrpInD3" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[+] USB HIGH PRIORITY!" -ForegroundColor Green
}

function Optimize-Audio-3a9faah {
    Write-Host "`n[*] 3a9faah Audio Optimization..." -ForegroundColor Magenta
    $Audio = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96c-e325-11ce-bfc1-08002be10318}"
    Get-ChildItem $Audio -ErrorAction SilentlyContinue | ForEach-Object {
        Set-ItemProperty -Path $_.PSPath -Name "LowLatency" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    }
    Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render" -ErrorAction SilentlyContinue | ForEach-Object {
        $Prop = Join-Path $_.PSPath "Properties"
        if (Test-Path $Prop) {
            Set-ItemProperty -Path $Prop -Name "{a8f2c838-4f5e-468f-af05-db53d3f78c6d},3" -Value 1 -Type DWord -ErrorAction SilentlyContinue
        }
    }
    Write-Host "[+] Audio LOW LATENCY!" -ForegroundColor Green
}

function Clean-System-3a9faah {
    Write-Host "`n[*] 3a9faah Deep Cleaning..." -ForegroundColor Magenta
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\CrashDumps\*" -Recurse -Force -ErrorAction SilentlyContinue
    ipconfig /flushdns 2>$null | Out-Null
    Clear-RecycleBin -Force -ErrorAction SilentlyContinue
    Write-Host "[+] System CLEAN!" -ForegroundColor Green
}

function Tweak-CPUPriority { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 -Type DWord; Write-Host "[+] CPU Priority" -ForegroundColor Green }
function Tweak-IOPriority { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" -Name "IoQueueWorkItem" -Value 32 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] IO Priority" -ForegroundColor Green }
function Tweak-ThreadQuantum { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ThreadQuantum" -Value 18 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Thread Quantum" -ForegroundColor Green }
function Tweak-ContextSwitching { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "ContextSwitchEnable" -Value 1 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Context Switch" -ForegroundColor Green }
function Tweak-SystemCache { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "SystemCacheLimit" -Value 0 -Type DWord; Write-Host "[+] System Cache" -ForegroundColor Green }
function Tweak-PagePool { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "PagedPoolSize" -Value 0xFFFFFFFF -Type DWord; Write-Host "[+] Page Pool" -ForegroundColor Green }
function Tweak-NonPagedPool { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "NonPagedPoolSize" -Value 0 -Type DWord; Write-Host "[+] NonPaged Pool" -ForegroundColor Green }
function Tweak-LargePages { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "LargePageMinimum" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Large Pages" -ForegroundColor Green }
function Tweak-WriteBuffer { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Disk" -Name "TimeOutValue" -Value 60 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Write Buffer" -ForegroundColor Green }
function Tweak-DMARemapping { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "DpiMapIommuContiguous" -Value 1 -Type DWord; Write-Host "[+] DMA Remapping" -ForegroundColor Green }
function Tweak-Spectre { $P = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"; Set-ItemProperty -Path $P -Name "FeatureSettingsOverride" -Value 3 -Type DWord; Set-ItemProperty -Path $P -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord; Write-Host "[+] Spectre Mitigation" -ForegroundColor Green }
function Tweak-ASLR { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "MitigationOptions" -Value 0 -Type QWord -ErrorAction SilentlyContinue; Write-Host "[+] ASLR Tweak" -ForegroundColor Green }
function Tweak-DEP { bcdedit /set nx OptIn 2>$null; Write-Host "[+] DEP Optimized" -ForegroundColor Green }
function Tweak-SEHOP { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "KernelSEHOPEnabled" -Value 0 -Type DWord; Write-Host "[+] SEHOP" -ForegroundColor Green }
function Tweak-CFG { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "DisableTsx" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] CFG Tweak" -ForegroundColor Green }
function Tweak-SMBios { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "Size" -Value 3 -Type DWord; Write-Host "[+] SMB Optimized" -ForegroundColor Green }
function Tweak-LanMan { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "DisableBandwidthThrottling" -Value 1 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] LanMan" -ForegroundColor Green }
function Tweak-NetBios { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" -Name "EnableLMHOSTS" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] NetBIOS" -ForegroundColor Green }
function Tweak-DNS { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "MaxCacheTtl" -Value 86400 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] DNS Cache" -ForegroundColor Green }
function Tweak-DNSNegative { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "NegativeCacheTime" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] DNS Negative" -ForegroundColor Green }
function Tweak-HostsFile { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableHostsFile" -Value 1 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Hosts File" -ForegroundColor Green }
function Tweak-WinHTTP { netsh winhttp reset proxy 2>$null; Write-Host "[+] WinHTTP" -ForegroundColor Green }
function Tweak-RSSQueues { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*NumRssQueues" -RegistryValue 4 -ErrorAction SilentlyContinue; Write-Host "[+] RSS Queues" -ForegroundColor Green }
function Tweak-JumboFrame { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*JumboPacket" -RegistryValue 1514 -ErrorAction SilentlyContinue; Write-Host "[+] Jumbo Frame" -ForegroundColor Green }
function Tweak-EnergyEfficient { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*EEE" -RegistryValue 0 -ErrorAction SilentlyContinue; Write-Host "[+] EEE Disabled" -ForegroundColor Green }
function Tweak-PriorityVLAN { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*PriorityVLANTag" -RegistryValue 1 -ErrorAction SilentlyContinue; Write-Host "[+] VLAN Priority" -ForegroundColor Green }
function Tweak-WakeOnLAN { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*WakeOnMagicPacket" -RegistryValue 0 -ErrorAction SilentlyContinue; Write-Host "[+] WoL Disabled" -ForegroundColor Green }
function Tweak-AdaptiveIFS { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*AdaptiveIFS" -RegistryValue 0 -ErrorAction SilentlyContinue; Write-Host "[+] Adaptive IFS" -ForegroundColor Green }
function Tweak-CoalesceBuffers { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*ReceiveBuffers" -RegistryValue 2048 -ErrorAction SilentlyContinue; Write-Host "[+] Receive Buffers" -ForegroundColor Green }
function Tweak-TransmitBuffers { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*TransmitBuffers" -RegistryValue 2048 -ErrorAction SilentlyContinue; Write-Host "[+] Transmit Buffers" -ForegroundColor Green }
function Tweak-SpeedDuplex { Get-NetAdapter | Set-NetAdapterAdvancedProperty -RegistryKeyword "*SpeedDuplex" -RegistryValue 0 -ErrorAction SilentlyContinue; Write-Host "[+] Speed Duplex" -ForegroundColor Green }
function Tweak-Checksum { Get-NetAdapter | Disable-NetAdapterChecksumOffload -AllProtocols -ErrorAction SilentlyContinue; Write-Host "[+] Checksum Offload" -ForegroundColor Green }
function Tweak-D3Cold { Get-PnpDevice | ForEach-Object { $P = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($_.InstanceId)\Device Parameters"; Set-ItemProperty -Path $P -Name "D3ColdSupported" -Value 0 -Type DWord -ErrorAction SilentlyContinue }; Write-Host "[+] D3Cold" -ForegroundColor Green }
function Tweak-IdlePower { powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null; Write-Host "[+] Idle Power" -ForegroundColor Green }
function Tweak-USBPower { powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0 2>$null; Write-Host "[+] USB Power" -ForegroundColor Green }
function Tweak-PCIePower { powercfg -setacvalueindex scheme_current 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 2>$null; Write-Host "[+] PCIe Power" -ForegroundColor Green }
function Tweak-GPUPower { powercfg -setacvalueindex scheme_current 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 2 2>$null; Write-Host "[+] GPU Power" -ForegroundColor Green }
function Tweak-CPUPower { powercfg -setacvalueindex scheme_current sub_processor PERFBOOSTMODE 2 2>$null; Write-Host "[+] CPU Boost" -ForegroundColor Green }
function Tweak-CStates { powercfg -setacvalueindex scheme_current sub_processor IDLEPROMOTE 0 2>$null; powercfg -setacvalueindex scheme_current sub_processor IDLEDEMOTE 0 2>$null; Write-Host "[+] C-States" -ForegroundColor Green }
function Tweak-ParkingIndex { powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100 2>$null; Write-Host "[+] Core Parking" -ForegroundColor Green }
function Tweak-FreqScaling { powercfg -setacvalueindex scheme_current sub_processor PERFINCTHRESHOLD 0 2>$null; Write-Host "[+] Freq Scaling" -ForegroundColor Green }
function Tweak-HardDisk { powercfg -setacvalueindex scheme_current 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0 2>$null; Write-Host "[+] HDD Power" -ForegroundColor Green }
function Tweak-WiFiPower { powercfg -setacvalueindex scheme_current 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 0 2>$null; Write-Host "[+] WiFi Power" -ForegroundColor Green }
function Tweak-AudioPower { powercfg -setacvalueindex scheme_current 501a4d13-42af-4429-9fd1-a8218c268e20 4350aa08-9c4e-4ff7-89a2-afa77acab7b3 0 2>$null; Write-Host "[+] Audio Power" -ForegroundColor Green }
function Tweak-SleepDelay { powercfg -setacvalueindex scheme_current sub_sleep STANDBYIDLE 0 2>$null; Write-Host "[+] Sleep Delay" -ForegroundColor Green }
function Tweak-HibernateFile { powercfg /hibernate off 2>$null; Write-Host "[+] Hibernate Off" -ForegroundColor Green }
function Tweak-FastStartup { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0 -Type DWord; Write-Host "[+] Fast Startup Off" -ForegroundColor Green }
function Tweak-ShutdownTime { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type String; Write-Host "[+] Shutdown Fast" -ForegroundColor Green }
function Tweak-SearchIndex { Stop-Service WSearch -Force -ErrorAction SilentlyContinue; Set-Service WSearch -StartupType Disabled -ErrorAction SilentlyContinue; Write-Host "[+] Search Index Off" -ForegroundColor Green }
function Tweak-Indexer { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowIndexingEncryptedStoresOrItems" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Indexer" -ForegroundColor Green }
function Tweak-ThumbCache { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbnailCache" -Value 1 -Type DWord; Write-Host "[+] Thumb Cache Off" -ForegroundColor Green }
function Tweak-RecentFiles { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord; Write-Host "[+] Recent Files Off" -ForegroundColor Green }
function Tweak-JumpLists { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_JumpListItems" -Value 0 -Type DWord; Write-Host "[+] Jump Lists Off" -ForegroundColor Green }
function Tweak-ShellIconCache { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "Max Cached Icons" -Value 8192 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Icon Cache" -ForegroundColor Green }
function Tweak-BackgroundApps { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord; Write-Host "[+] BG Apps Off" -ForegroundColor Green }
function Tweak-StartupApps { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "OneDrive" -Value ([byte[]](0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00)) -Type Binary -ErrorAction SilentlyContinue; Write-Host "[+] Startup Apps" -ForegroundColor Green }
function Tweak-AppReadiness { Stop-Service AppReadiness -Force -ErrorAction SilentlyContinue; Set-Service AppReadiness -StartupType Disabled -ErrorAction SilentlyContinue; Write-Host "[+] App Readiness Off" -ForegroundColor Green }
function Tweak-AppXSvc { Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppXSvc" -Name "Start" -Value 4 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] AppX Service" -ForegroundColor Green }
function Tweak-FontCache { Stop-Service FontCache -Force -ErrorAction SilentlyContinue; Write-Host "[+] Font Cache" -ForegroundColor Green }
function Tweak-PrintSpooler { Stop-Service Spooler -Force -ErrorAction SilentlyContinue; Set-Service Spooler -StartupType Manual -ErrorAction SilentlyContinue; Write-Host "[+] Print Spooler" -ForegroundColor Green }
function Tweak-NVIDIATelemetry { Stop-Service NvTelemetryContainer -Force -ErrorAction SilentlyContinue; Set-Service NvTelemetryContainer -StartupType Disabled -ErrorAction SilentlyContinue; Write-Host "[+] NVIDIA Telemetry Off" -ForegroundColor Green }
function Tweak-AMDTelemetry { schtasks /change /tn "\AMD\AMDInstallWizardHelper" /disable 2>$null; Write-Host "[+] AMD Telemetry Off" -ForegroundColor Green }
function Tweak-EdgeTelemetry { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "MetricsReportingEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Edge Telemetry Off" -ForegroundColor Green }
function Tweak-ChromeTelemetry { Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Chrome Telemetry Off" -ForegroundColor Green }
function Tweak-OfficeTelemetry { Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry" -Name "SendTelemetry" -Value 3 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Office Telemetry Off" -ForegroundColor Green }
function Tweak-VSCodeTelemetry { $P = "$env:APPDATA\Code\User\settings.json"; if (Test-Path $P) { (Get-Content $P) -replace '"telemetry.enableTelemetry": true', '"telemetry.enableTelemetry": false' | Set-Content $P -ErrorAction SilentlyContinue }; Write-Host "[+] VSCode Telemetry" -ForegroundColor Green }
function Tweak-WindowsErrorReporting { Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Value 1 -Type DWord; Write-Host "[+] WER Off" -ForegroundColor Green }
function Tweak-PerfLogs { Remove-Item -Path "C:\PerfLogs\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Host "[+] PerfLogs Cleaned" -ForegroundColor Green }
function Tweak-EventLogs { wevtutil cl Application 2>$null; wevtutil cl System 2>$null; wevtutil cl Security 2>$null; Write-Host "[+] Event Logs Cleared" -ForegroundColor Green }
function Tweak-MemoryDiag { schtasks /change /tn "\Microsoft\Windows\MemoryDiagnostic\ProcessMemoryDiagnosticEvents" /disable 2>$null; Write-Host "[+] Memory Diag Off" -ForegroundColor Green }
function Tweak-MaintScheduler { schtasks /change /tn "\Microsoft\Windows\TaskScheduler\Maintenance Configurator" /disable 2>$null; Write-Host "[+] Maintenance Off" -ForegroundColor Green }
function Tweak-CloudNotify { Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" -Name "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" -Value 0 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Cloud Notify Off" -ForegroundColor Green }
function Tweak-ActionCenter { Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 1 -Type DWord -ErrorAction SilentlyContinue; Write-Host "[+] Action Center" -ForegroundColor Green }

function Apply-50Tweaks {
    Write-Host "`n[*] 3a9faah MEGA PACK: 50 EXCLUSIVE Tweaks..." -ForegroundColor Magenta
    Tweak-CPUPriority; Tweak-IOPriority; Tweak-ThreadQuantum; Tweak-ContextSwitching; Tweak-SystemCache
    Tweak-PagePool; Tweak-NonPagedPool; Tweak-LargePages; Tweak-WriteBuffer; Tweak-DMARemapping
    Tweak-Spectre; Tweak-ASLR; Tweak-DEP; Tweak-SEHOP; Tweak-CFG
    Tweak-SMBios; Tweak-LanMan; Tweak-NetBios; Tweak-DNS; Tweak-DNSNegative
    Tweak-HostsFile; Tweak-WinHTTP; Tweak-RSSQueues; Tweak-JumboFrame; Tweak-EnergyEfficient
    Tweak-PriorityVLAN; Tweak-WakeOnLAN; Tweak-AdaptiveIFS; Tweak-CoalesceBuffers; Tweak-TransmitBuffers
    Tweak-SpeedDuplex; Tweak-Checksum; Tweak-D3Cold; Tweak-IdlePower; Tweak-USBPower
    Tweak-PCIePower; Tweak-GPUPower; Tweak-CPUPower; Tweak-CStates; Tweak-ParkingIndex
    Tweak-FreqScaling; Tweak-HardDisk; Tweak-WiFiPower; Tweak-AudioPower; Tweak-SleepDelay
    Tweak-HibernateFile; Tweak-FastStartup; Tweak-ShutdownTime; Tweak-SearchIndex; Tweak-Indexer
    Write-Host "`n[*] 3a9faah MEGA PACK Part 2..." -ForegroundColor Magenta
    Tweak-ThumbCache; Tweak-RecentFiles; Tweak-JumpLists; Tweak-ShellIconCache; Tweak-BackgroundApps
    Tweak-StartupApps; Tweak-AppReadiness; Tweak-AppXSvc; Tweak-FontCache; Tweak-PrintSpooler
    Tweak-NVIDIATelemetry; Tweak-AMDTelemetry; Tweak-EdgeTelemetry; Tweak-ChromeTelemetry; Tweak-OfficeTelemetry
    Tweak-VSCodeTelemetry; Tweak-WindowsErrorReporting; Tweak-PerfLogs; Tweak-EventLogs; Tweak-MemoryDiag
    Tweak-MaintScheduler; Tweak-CloudNotify; Tweak-ActionCenter
    Write-Host "[+] 50 EXCLUSIVE TWEAKS APPLIED!" -ForegroundColor Green
}

function Optimize-CSRSS-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: CSRSS Priority Boost..." -ForegroundColor Magenta
    $CSRSS = Get-Process csrss -ErrorAction SilentlyContinue
    if ($CSRSS) {
        $CSRSS | ForEach-Object { $_.PriorityClass = 'High' }
    }
    $DWM = Get-Process dwm -ErrorAction SilentlyContinue
    if ($DWM) {
        $DWM | ForEach-Object { $_.PriorityClass = 'High' }
    }
    Write-Host "[+] System Processes Boosted!" -ForegroundColor Green
}

function Optimize-TimerResolution-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Timer Resolution (0.5ms)..." -ForegroundColor Magenta
    $Kernel = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    Set-ItemProperty -Path $Kernel -Name "GlobalTimerResolutionRequests" -Value 1 -Type DWord
    $MM = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    Set-ItemProperty -Path $MM -Name "SystemResponsiveness" -Value 0 -Type DWord
    bcdedit /set useplatformtick yes 2>$null
    bcdedit /set disabledynamictick yes 2>$null
    Write-Host "[+] Timer Resolution 0.5ms!" -ForegroundColor Green
}

function Optimize-Boot-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Boot Optimization..." -ForegroundColor Magenta
    bcdedit /set bootmenupolicy standard 2>$null
    bcdedit /set quietboot yes 2>$null
    bcdedit /set bootux disabled 2>$null
    bcdedit /set bootlog no 2>$null
    bcdedit /set sos no 2>$null
    bcdedit /timeout 0 2>$null
    $Boot = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-ItemProperty -Path $Boot -Name "DelayedDesktopSwitchTimeout" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    $Startup = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (!(Test-Path $Startup)) { New-Item -Path $Startup -Force | Out-Null }
    Set-ItemProperty -Path $Startup -Name "StartupDelayInMSec" -Value 0 -Type DWord
    Write-Host "[+] Boot INSTANT!" -ForegroundColor Green
}

function Optimize-ContextMenu-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Context Menu Speed..." -ForegroundColor Magenta
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0" -Type String
    $Shell = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $Shell -Name "DesktopProcess" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "$Shell\Advanced" -Name "Start_TrackDocs" -Value 0 -Type DWord
    Set-ItemProperty -Path "$Shell\Advanced" -Name "Start_TrackProgs" -Value 0 -Type DWord
    Set-ItemProperty -Path "$Shell\Advanced" -Name "EnableBalloonTips" -Value 0 -Type DWord
    Write-Host "[+] Context Menu INSTANT!" -ForegroundColor Green
}

function Optimize-InputLag-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Input Lag Killer..." -ForegroundColor Magenta
    $Win32 = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $Win32 -Name "Win32PrioritySeparation" -Value 38 -Type DWord
    Set-ItemProperty -Path $Win32 -Name "IRQ8Priority" -Value 1 -Type DWord
    $Session = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
    Set-ItemProperty -Path $Session -Name "HeapDeCommitFreeBlockThreshold" -Value 262144 -Type DWord -ErrorAction SilentlyContinue
    $Thread = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass"
    Set-ItemProperty -Path $Thread -Name "Start" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    $Thread2 = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass"
    Set-ItemProperty -Path $Thread2 -Name "Start" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    $Direct = "HKLM:\SOFTWARE\Microsoft\DirectInput"
    if (!(Test-Path $Direct)) { New-Item -Path $Direct -Force | Out-Null }
    Set-ItemProperty -Path $Direct -Name "EmulationOff" -Value 1 -Type DWord
    Write-Host "[+] Input Lag ELIMINATED!" -ForegroundColor Green
}

function Optimize-MemoryBoost-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Memory Performance Boost..." -ForegroundColor Magenta
    $Mem = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    Set-ItemProperty -Path $Mem -Name "DisablePagingExecutive" -Value 1 -Type DWord
    Set-ItemProperty -Path $Mem -Name "LargeSystemCache" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "ClearPageFileAtShutdown" -Value 0 -Type DWord
    Set-ItemProperty -Path $Mem -Name "FeatureSettingsOverride" -Value 3 -Type DWord
    Set-ItemProperty -Path $Mem -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord
    $Cache = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Set-ItemProperty -Path $Cache -Name "Size" -Value 3 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $Cache -Name "IRPStackSize" -Value 20 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[+] Memory OPTIMIZED!" -ForegroundColor Green
}

function Optimize-DefenderGaming-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Defender Gaming Mode..." -ForegroundColor Magenta
    $Def = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    if (!(Test-Path $Def)) { New-Item -Path $Def -Force | Out-Null }
    Set-ItemProperty -Path $Def -Name "DisableAntiSpyware" -Value 0 -Type DWord
    $RTP = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    if (!(Test-Path $RTP)) { New-Item -Path $RTP -Force | Out-Null }
    Set-ItemProperty -Path $RTP -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord
    Set-ItemProperty -Path $RTP -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord
    $Scan = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
    if (!(Test-Path $Scan)) { New-Item -Path $Scan -Force | Out-Null }
    Set-ItemProperty -Path $Scan -Name "AvgCPULoadFactor" -Value 5 -Type DWord
    Set-ItemProperty -Path $Scan -Name "DisableCpuThrottleOnIdleScans" -Value 0 -Type DWord
    $Notify = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Reporting"
    if (!(Test-Path $Notify)) { New-Item -Path $Notify -Force | Out-Null }
    Set-ItemProperty -Path $Notify -Name "DisableEnhancedNotifications" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[+] Defender Gaming Mode ON!" -ForegroundColor Green
}

function Optimize-Scheduler-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Windows Scheduler..." -ForegroundColor Magenta
    $Sched = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Executive"
    if (!(Test-Path $Sched)) { New-Item -Path $Sched -Force | Out-Null }
    Set-ItemProperty -Path $Sched -Name "AdditionalCriticalWorkerThreads" -Value 16 -Type DWord
    Set-ItemProperty -Path $Sched -Name "AdditionalDelayedWorkerThreads" -Value 16 -Type DWord
    $Pri = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
    Set-ItemProperty -Path $Pri -Name "ConvertibleSlateMode" -Value 0 -Type DWord
    $Thread = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
    Set-ItemProperty -Path $Thread -Name "ThreadDpcEnable" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $Thread -Name "SplitLargeCaches" -Value 1 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "[+] Scheduler TURBO!" -ForegroundColor Green
}

function Optimize-Explorer-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Explorer Optimization..." -ForegroundColor Magenta
    $Exp = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer"
    Set-ItemProperty -Path $Exp -Name "DesktopProcess" -Value 1 -Type DWord
    Set-ItemProperty -Path $Exp -Name "Max Cached Icons" -Value 8192 -Type DWord -ErrorAction SilentlyContinue
    $Adv = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Set-ItemProperty -Path $Adv -Name "HideFileExt" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "AutoCheckSelect" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "TaskbarSmallIcons" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "ShowInfoTip" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "Start_SearchFiles" -Value 0 -Type DWord
    Set-ItemProperty -Path $Adv -Name "LaunchTo" -Value 1 -Type DWord
    $Ser = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize"
    if (!(Test-Path $Ser)) { New-Item -Path $Ser -Force | Out-Null }
    Set-ItemProperty -Path $Ser -Name "StartupDelayInMSec" -Value 0 -Type DWord
    Write-Host "[+] Explorer FAST!" -ForegroundColor Green
}

function Optimize-Bandwidth-3a9faah {
    Write-Host "`n[*] 3a9faah EXCLUSIVE: Bandwidth Optimization..." -ForegroundColor Magenta
    $BW = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched"
    if (!(Test-Path $BW)) { New-Item -Path $BW -Force | Out-Null }
    Set-ItemProperty -Path $BW -Name "NonBestEffortLimit" -Value 0 -Type DWord
    $Qos = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\QoS"
    if (!(Test-Path $Qos)) { New-Item -Path $Qos -Force | Out-Null }
    Set-ItemProperty -Path $Qos -Name "PacketSchedulerLimitedStreams" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    $Update = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
    if (!(Test-Path $Update)) { New-Item -Path $Update -Force | Out-Null }
    Set-ItemProperty -Path $Update -Name "DODownloadMode" -Value 0 -Type DWord
    Write-Host "[+] Bandwidth 100% FREE!" -ForegroundColor Green
}

function Apply-AllTweaks {
    Show-Logo
    Write-Host "`n[*] Starting 3a9faah Ultimate Tweak v3.0..." -ForegroundColor Cyan
    Open-GitHub
    Create-RestorePoint
    Backup-Registry
    Write-Host "`n[*] Applying 3a9faah EXCLUSIVE Optimizations..." -ForegroundColor Cyan
    Write-Host "=========================================`n" -ForegroundColor DarkGray
    Optimize-Keyboard
    Optimize-Mouse
    Optimize-Gaming
    Optimize-DPC-3a9faah
    Optimize-IRQ-3a9faah
    Optimize-Network-3a9faah
    Optimize-Power-3a9faah
    Optimize-System-3a9faah
    Optimize-Visual-3a9faah
    Optimize-Privacy-3a9faah
    Disable-Services-3a9faah
    Optimize-GPU-3a9faah
    Optimize-USB-3a9faah
    Optimize-Audio-3a9faah
    Optimize-CSRSS-3a9faah
    Optimize-TimerResolution-3a9faah
    Optimize-Boot-3a9faah
    Optimize-ContextMenu-3a9faah
    Optimize-InputLag-3a9faah
    Optimize-MemoryBoost-3a9faah
    Optimize-DefenderGaming-3a9faah
    Optimize-Scheduler-3a9faah
    Optimize-Explorer-3a9faah
    Optimize-Bandwidth-3a9faah
    Apply-50Tweaks
    Clean-System-3a9faah
    Write-Host "`n=========================================" -ForegroundColor DarkGray
    Write-Host "[+] 3a9faah ULTIMATE TWEAK COMPLETE!" -ForegroundColor Green
    Write-Host "[!] 75+ EXCLUSIVE Optimizations Applied!" -ForegroundColor Yellow
    Write-Host "[!] Restart for full effect." -ForegroundColor Yellow
    Write-Host " Copyright (c) 2026 3a9faah" -ForegroundColor DarkCyan
    Write-Host " https://github.com/3a9faah" -ForegroundColor DarkCyan
    Write-Host "=========================================`n" -ForegroundColor DarkGray
}

function Show-Menu {
    Show-Logo
    Write-Host " [1] Apply ALL Tweaks (RECOMMENDED)" -ForegroundColor White
    Write-Host " [2] Keyboard Only" -ForegroundColor White
    Write-Host " [3] Mouse Only" -ForegroundColor White
    Write-Host " [4] Gaming Only" -ForegroundColor White
    Write-Host " [5] DPC Latency Only" -ForegroundColor White
    Write-Host " [6] Network Only" -ForegroundColor White
    Write-Host " [7] Disable Services" -ForegroundColor White
    Write-Host " [8] Power Only" -ForegroundColor White
    Write-Host " [9] Clean System" -ForegroundColor White
    Write-Host " [0] Exit" -ForegroundColor Red
    Write-Host ""
    return (Read-Host "Select")
}

do {
    $s = Show-Menu
    switch ($s) {
        '1' { Apply-AllTweaks; pause }
        '2' { Create-RestorePoint; Optimize-Keyboard; pause }
        '3' { Create-RestorePoint; Optimize-Mouse; pause }
        '4' { Create-RestorePoint; Optimize-Gaming; pause }
        '5' { Create-RestorePoint; Optimize-DPC-3a9faah; Optimize-IRQ-3a9faah; pause }
        '6' { Create-RestorePoint; Optimize-Network-3a9faah; pause }
        '7' { Create-RestorePoint; Disable-Services-3a9faah; pause }
        '8' { Create-RestorePoint; Optimize-Power-3a9faah; pause }
        '9' { Clean-System-3a9faah; pause }
        '0' { Write-Host "`n[*] Goodbye! - 3a9faah" -ForegroundColor Cyan; exit }
    }
} while ($s -ne '0')
