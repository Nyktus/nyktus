Import-Module ActiveDirectory
New-ADComputer -Name 'fs-archive01' -SamAccountName 'fs-archive01$' -DNSHostName 'computerq3xwz7a2kfm4ub6tyc5nre.d.example.net' -Enabled $true
