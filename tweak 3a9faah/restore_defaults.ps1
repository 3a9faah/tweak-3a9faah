# ============================================================================
# 3a9faah Restore Defaults Tool
# Copyright (c) 2026 3a9faah - All Rights Reserved
# GitHub: https://github.com/3a9faah
# ============================================================================
# This script restores Windows to default settings
# ============================================================================

#Requires -RunAsAdministrator

$Host.UI.RawUI.WindowTitle = "3a9faah Restore Tool"
$ErrorActionPreference = "SilentlyContinue"

$Logo = @"
===============================================================================
   ____        ___   __            _     
  |___ \      / _ \ / _|          | |    
    __) | __ | (_) | |_ __ _  __ _| |__  
   |__ < / _` \__, |  _/ _` |/ _` | '_ \ 
   ___) | (_| | / /| || (_| | (_| | | | |
  |____/ \__,_|/_/ |_| \__,_|\__,_|_| |_|
                                         
  RESTORE DEFAULTS TOOL v2.0
  Copyright (c) 2026 3a9faah
===============================================================================
"@

Clear-Host
Write-Host $Logo -ForegroundColor Cyan
Write-Host ""
Write-Host "[!] This will restore Windows to default settings." -ForegroundColor Yellow
Write-Host "[!] Some changes may require a restart." -ForegroundColor Yellow
Write-Host ""

$confirm = Read-Host "Are you sure you want to restore defaults? (Y/N)"
if ($confirm -ne 'Y' -and $confirm -ne 'y') {
    Write-Host "[*] Cancelled." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "[*] Restoring Defaults..." -ForegroundColor Cyan
Write-Host ""

Write-Host "[*] Restoring Keyboard Settings..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Value 1 -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardSpeed" -Value 31 -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatDelay" -Value "1000" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatRate" -Value "500" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "DelayBeforeAcceptance" -Value "1000" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value "126" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "BounceTime" -Value "0" -Type String
Write-Host "[+] Keyboard Restored" -ForegroundColor Green

Write-Host "[*] Restoring Mouse Settings..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "1" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "6" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "10" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Value "10" -Type String
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Value "400" -Type String
Write-Host "[+] Mouse Restored" -ForegroundColor Green

Write-Host "[*] Restoring Gaming Settings..." -ForegroundColor Yellow
$GameDVR = "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR"
if (Test-Path $GameDVR) {
    Set-ItemProperty -Path $GameDVR -Name "AppCaptureEnabled" -Value 1 -Type DWord
}
$GameConfigStore = "HKCU:\System\GameConfigStore"
if (Test-Path $GameConfigStore) {
    Set-ItemProperty -Path $GameConfigStore -Name "GameDVR_Enabled" -Value 1 -Type DWord
}
Write-Host "[+] Gaming Restored" -ForegroundColor Green

Write-Host "[*] Restoring DPC Settings..." -ForegroundColor Yellow
$Multimedia = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
Set-ItemProperty -Path $Multimedia -Name "NetworkThrottlingIndex" -Value 10 -Type DWord
Set-ItemProperty -Path $Multimedia -Name "SystemResponsiveness" -Value 20 -Type DWord

bcdedit /deletevalue disabledynamictick 2>$null
bcdedit /deletevalue useplatformtick 2>$null
bcdedit /deletevalue tscsyncpolicy 2>$null
bcdedit /deletevalue useplatformclock 2>$null
Write-Host "[+] DPC Restored" -ForegroundColor Green

Write-Host "[*] Restoring Network Settings..." -ForegroundColor Yellow
$TCPIPParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
Remove-ItemProperty -Path $TCPIPParams -Name "TcpAckFrequency" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $TCPIPParams -Name "TCPNoDelay" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $TCPIPParams -Name "TcpDelAckTicks" -ErrorAction SilentlyContinue

netsh int tcp set global autotuninglevel=normal 2>$null
netsh int tcp set global ecncapability=default 2>$null
netsh int tcp set global timestamps=default 2>$null
Write-Host "[+] Network Restored" -ForegroundColor Green

Write-Host "[*] Restoring Power Settings..." -ForegroundColor Yellow
powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e 2>$null
powercfg -delete 99999999-9999-9999-9999-999999999999 2>$null
powercfg /hibernate on 2>$null

$PowerThrottling = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
if (Test-Path $PowerThrottling) {
    Remove-ItemProperty -Path $PowerThrottling -Name "PowerThrottlingOff" -ErrorAction SilentlyContinue
}
Write-Host "[+] Power Restored" -ForegroundColor Green

Write-Host "[*] Restoring System Settings..." -ForegroundColor Yellow
$Prefetch = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
Set-ItemProperty -Path $Prefetch -Name "EnablePrefetcher" -Value 3 -Type DWord
Set-ItemProperty -Path $Prefetch -Name "EnableSuperfetch" -Value 3 -Type DWord

$Desktop = "HKCU:\Control Panel\Desktop"
Set-ItemProperty -Path $Desktop -Name "AutoEndTasks" -Value "0" -Type String
Set-ItemProperty -Path $Desktop -Name "HungAppTimeout" -Value "5000" -Type String
Set-ItemProperty -Path $Desktop -Name "WaitToKillAppTimeout" -Value "20000" -Type String
Set-ItemProperty -Path $Desktop -Name "MenuShowDelay" -Value "400" -Type String

$Control = "HKLM:\SYSTEM\CurrentControlSet\Control"
Set-ItemProperty -Path $Control -Name "WaitToKillServiceTimeout" -Value "5000" -Type String

$FileSystem = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
Set-ItemProperty -Path $FileSystem -Name "NtfsDisableLastAccessUpdate" -Value 0 -Type DWord
Set-ItemProperty -Path $FileSystem -Name "NtfsDisable8dot3NameCreation" -Value 0 -Type DWord
Write-Host "[+] System Restored" -ForegroundColor Green

Write-Host "[*] Restoring Visual Effects..." -ForegroundColor Yellow
$Visual = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
if (Test-Path $Visual) {
    Set-ItemProperty -Path $Visual -Name "VisualFXSetting" -Value 0 -Type DWord
}

$Themes = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
Set-ItemProperty -Path $Themes -Name "EnableTransparency" -Value 1 -Type DWord

$DWM = "HKCU:\Software\Microsoft\Windows\DWM"
Set-ItemProperty -Path $DWM -Name "EnableAeroPeek" -Value 1 -Type DWord
Write-Host "[+] Visual Effects Restored" -ForegroundColor Green

Write-Host "[*] Restoring Services..." -ForegroundColor Yellow
$ServicesToEnable = @(
    "SysMain"
    "WSearch"
    "DiagTrack"
)

foreach ($Service in $ServicesToEnable) {
    Set-Service -Name $Service -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name $Service -ErrorAction SilentlyContinue
    Write-Host "  [+] Enabled: $Service" -ForegroundColor DarkGray
}
Write-Host "[+] Services Restored" -ForegroundColor Green

Write-Host "[*] Restoring Scheduled Tasks..." -ForegroundColor Yellow
schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /enable 2>$null
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /enable 2>$null
schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /enable 2>$null
Write-Host "[+] Scheduled Tasks Restored" -ForegroundColor Green

Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "[+] ALL DEFAULTS RESTORED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "[!] Please restart your computer." -ForegroundColor Yellow
Write-Host ""
Write-Host " Copyright (c) 2026 3a9faah" -ForegroundColor DarkCyan
Write-Host " GitHub: https://github.com/3a9faah" -ForegroundColor DarkCyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
pause
