$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$bytes = New-Object byte[] 48
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$generator.GetBytes($bytes)
$generator.Dispose()
$plain = [Convert]::ToBase64String($bytes) + 'aA1!'
$password = ConvertTo-SecureString $plain -AsPlainText -Force
New-ADUser -Name 'svc-reporting' -SamAccountName 'svc-reporting' -UserPrincipalName 'svc-reporting@corp.example.com' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -ServicePrincipalNames 'MSSQLSvc/sql-reporting01.corp.example.com:1433'
