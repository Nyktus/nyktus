$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$bytes = New-Object byte[] 48
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$generator.GetBytes($bytes)
$generator.Dispose()
$plain = [Convert]::ToBase64String($bytes) + 'aA1!'
$password = ConvertTo-SecureString $plain -AsPlainText -Force
New-ADUser -Name 'svc-legacy-scan' -SamAccountName 'svc-legacy-scan' -UserPrincipalName 'svc-legacy-scan@corp.example.com' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
Set-ADAccountControl -Identity 'svc-legacy-scan' -DoesNotRequirePreAuth $true
