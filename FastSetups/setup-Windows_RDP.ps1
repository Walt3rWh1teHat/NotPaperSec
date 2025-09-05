<#
.SYNOPSIS
    Secure & anonymous setup script for Windows VDS (10/11) via RDP.
.DESCRIPTION
    Этап 1: безопасная настройка без потери доступа.
    Этап 2: усиление защиты (смена RDP-порта, firewall).
    Запускать только от имени администратора!
#>

param(
    [switch]$Stage2
)

if (-not $Stage2) {
    Write-Output "=== Этап 1: Базовая настройка (безопасный режим) ==="

    # === 1. Обновления системы ===
    Write-Output "[*] Включение Windows Update..."
    Set-Service wuauserv -StartupType Automatic
    Start-Service wuauserv

    # === 2. Defender и защита ===
    Write-Output "[*] Настройка Windows Defender..."
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -PUAProtection Enabled
    Set-MpPreference -MAPSReporting 0
    Set-MpPreference -SubmitSamplesConsent 2

    # === 3. Отключение телеметрии ===
    Write-Output "[*] Отключение телеметрии..."
    Stop-Service diagtrack -Force
    Set-Service diagtrack -StartupType Disabled
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

    # === 4. Создание нового администратора ===
    $newUser = "secadmin"
    $newPass = Read-Host "Введите сложный пароль для нового администратора" -AsSecureString
    Write-Output "[*] Создание аккаунта $newUser..."
    New-LocalUser $newUser -Password $newPass -FullName "Secure Admin" -Description "Secured Admin Account"
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    Disable-LocalUser -Name "Administrator"

    # === 5. Отключение устаревших протоколов ===
    Write-Output "[*] Отключение устаревших протоколов..."
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 0 /f
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 0 /f

    # === 6. DNS-over-HTTPS (Cloudflare) ===
    Write-Output "[*] Настройка DNS over HTTPS..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v EnableAutoDoh /t REG_DWORD /d 2 /f

    # === 7. Очистка следов ===
    Write-Output "[*] Очистка журналов..."
    wevtutil el | ForEach-Object { wevtutil cl $_ }

    Write-Output "=== Этап 1 завершён. ==="
    Write-Output "Теперь выйди и войди под пользователем 'secadmin', чтобы проверить доступ."
    Write-Output "Когда будешь готов — запусти скрипт с параметром -Stage2 для усиленной защиты."
}
else {
    Write-Output "=== Этап 2: Усиленная защита (смена порта и firewall) ==="

    # === 1. Новый порт RDP ===
    $RDPport = Get-Random -Minimum 40000 -Maximum 50000
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "PortNumber" -Value $RDPport

    # === 2. Ограничение попыток входа ===
    net accounts /lockoutthreshold:3 /lockoutduration:30 /lockoutwindow:30

    # === 3. Брандмауэр: пока открыто всем (IP-фильтр добавь вручную при необходимости)
    New-NetFirewallRule -DisplayName "Allow RDP Secure" -Direction Inbound -Protocol TCP -LocalPort $RDPport -Action Allow

    Write-Output "=== Этап 2 завершён. ==="
    Write-Output "Теперь используй подключение: IP:$RDPport"
    Write-Output "mstsc /v:<IP-адрес>:$RDPport"
    Write-Output "Не забудь перезагрузить сервер!"
}
