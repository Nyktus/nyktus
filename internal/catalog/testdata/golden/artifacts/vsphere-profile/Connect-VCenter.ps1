$server = 'vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net'
$user = 'svc-vmops@vsphere.local'
$password = ConvertTo-SecureString 'Xy7Xy7Xy7Xy7Xy7Xy7Xy' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $password)
Connect-VIServer -Server $server -Credential $credential
Get-VM | Select-Object Name, PowerState
