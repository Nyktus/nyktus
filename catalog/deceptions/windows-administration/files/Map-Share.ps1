$server = 'Honeytoken-Domain-Share'
$user = 'CORP\svc-ops'
$password = ConvertTo-SecureString '98AkS6uylaoLjeO6U9mh' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $password)
New-PSDrive -Name O -PSProvider FileSystem -Root "\\$server\ops" -Credential $credential | Out-Null
Get-ChildItem O:\ | Sort-Object LastWriteTime -Descending | Select-Object -First 10
Remove-PSDrive -Name O
