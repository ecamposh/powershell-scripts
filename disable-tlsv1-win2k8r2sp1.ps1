# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    exit
}

# Disable TLS 1.0 and TLS 1.1
Write-Host "Disabling TLS 1.0 and TLS 1.1..."

# Registry paths for TLS settings
$tls10ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
$tls10ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
$tls11ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
$tls11ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"

# Create registry paths if they don't exist
New-Item -Path $tls10ServerPath -Force | Out-Null
New-Item -Path $tls10ClientPath -Force | Out-Null
New-Item -Path $tls11ServerPath -Force | Out-Null
New-Item -Path $tls11ClientPath -Force | Out-Null

# Disable TLS 1.0 Server
Set-ItemProperty -Path $tls10ServerPath -Name "Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path $tls10ServerPath -Name "DisabledByDefault" -Value 1 -Type DWORD

# Disable TLS 1.0 Client
Set-ItemProperty -Path $tls10ClientPath -Name "Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path $tls10ClientPath -Name "DisabledByDefault" -Value 1 -Type DWORD

# Disable TLS 1.1 Server
Set-ItemProperty -Path $tls11ServerPath -Name "Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path $tls11ServerPath -Name "DisabledByDefault" -Value 1 -Type DWORD

# Disable TLS 1.1 Client
Set-ItemProperty -Path $tls11ClientPath -Name "Enabled" -Value 0 -Type DWORD
Set-ItemProperty -Path $tls11ClientPath -Name "DisabledByDefault" -Value 1 -Type DWORD

Write-Host "TLS 1.0 and TLS 1.1 have been disabled."

# Disable weak ciphers
Write-Host "Disabling weak ciphers..."

$cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

# List of weak ciphers to disable
$weakCiphers = @(
    "DES 56/56",
    "RC2 40/128",
    "RC2 56/128",
    "RC2 128/128",
    "RC4 40/128",
    "RC4 56/128",
    "RC4 64/128",
    "RC4 128/128",
    "NULL"
)

foreach ($cipher in $weakCiphers) {
    $cipherRegPath = "$cipherPath\$cipher"
    New-Item -Path $cipherRegPath -Force | Out-Null
    Set-ItemProperty -Path $cipherRegPath -Name "Enabled" -Value 0 -Type DWORD
    Write-Host "Disabled cipher: $cipher"
}

# Enable strong ciphers (ensure AES ciphers are available)
$strongCiphers = @(
    "AES 128/128",
    "AES 256/256"
)

foreach ($cipher in $strongCiphers) {
    $cipherRegPath = "$cipherPath\$cipher"
    New-Item -Path $cipherRegPath -Force | Out-Null
    Set-ItemProperty -Path $cipherRegPath -Name "Enabled" -Value 0xFFFFFFFF -Type DWORD
    Write-Host "Ensured cipher enabled: $cipher"
}

Write-Host "Weak ciphers have been disabled."

# Notify user to reboot
Write-Host "Please reboot the server for changes to take effect." -ForegroundColor Yellow
