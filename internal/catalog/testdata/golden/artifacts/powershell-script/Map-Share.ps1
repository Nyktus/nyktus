$server = 'shareq3xwz7a2kfm4ub6tyc5nre.d.example.net'
$user = 'CORP\svc-ops'
$password = ConvertTo-SecureString 'Xy7Xy7Xy7Xy7Xy7Xy7Xy' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $password)
New-PSDrive -Name O -PSProvider FileSystem -Root "\\$server\ops" -Credential $credential | Out-Null
Get-ChildItem O:\ | Sort-Object LastWriteTime -Descending | Select-Object -First 10
Remove-PSDrive -Name O
