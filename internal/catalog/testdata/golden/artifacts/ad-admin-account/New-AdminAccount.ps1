$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$bytes = New-Object byte[] 48
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$generator.GetBytes($bytes)
$generator.Dispose()
$plain = [Convert]::ToBase64String($bytes) + 'aA1!'
$password = ConvertTo-SecureString $plain -AsPlainText -Force
New-ADUser -Name 'adm-backup' -SamAccountName 'adm-backup' -UserPrincipalName 'adm-backup@corp.example.com' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
