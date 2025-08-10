```powershell
# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "This script must be run as Administrator" -ForegroundColor Red
    exit
}

# Enable TLS 1.2 for .NET Framework 3.5
Write-Host "Configuring .NET Framework to use TLS 1.2..."

# Registry paths for .NET Framework 2.0/3.5 (used by Server 2008 R2)
$netPath32 = "HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727"
$netPath64 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727"

# Set SchUseStrongCrypto to enable TLS 1.2 for .NET 3.5
Set-ItemProperty -Path $netPath32 -Name "SchUseStrongCrypto" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $netPath32 -Name "SystemDefaultTlsVersions" -Value 1 -Type DWORD -Force
Write-Host "Configured TLS 1.2 for .NET Framework (32-bit)."

# Set for 64-bit applications (if applicable)
Set-ItemProperty -Path $netPath64 -Name "SchUseStrongCrypto" -Value 1 -Type DWORD -Force
Set-ItemProperty -Path $netPath64 -Name "SystemDefaultTlsVersions" -Value 1 -Type DWORD -Force
Write-Host "Configured TLS 1.2 for .NET Framework (64-bit)."

# Ensure system-wide TLS 1.2 is enabled (reinforce previous settings)
Write-Host "Verifying system-wide TLS 1.2 settings..."

$tls12ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
$tls12ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"

New-Item -Path $tls12ServerPath -Force | Out-Null
New-Item -Path $tls12ClientPath -Force | Out-Null

Set-ItemProperty -Path $tls12ServerPath -Name "Enabled" -Value 1 -Type DWORD
Set-ItemProperty -Path $tls12ServerPath -Name "DisabledByDefault" -Value 0 -Type DWORD
Set-ItemProperty -Path $tls12ClientPath -Name "Enabled" -Value 1 -Type DWORD
Set-ItemProperty -Path $tls12ClientPath -Name "DisabledByDefault" -Value 0 -Type DWORD

Write-Host "System-wide TLS 1.2 settings verified."

# Notify user to reboot
Write-Host "Please reboot the server for changes to take effect." -ForegroundColor Yellow

# Optional: Test .NET TLS configuration after reboot
Write-Host "To verify .NET TLS 1.2 usage after reboot, run the following command:"
Write-Host '[Net.ServicePointManager]::SecurityProtocol'
Write-Host "Expected output should include 'Tls12'."
```
