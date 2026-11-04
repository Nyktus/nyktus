$server = 'Honeytoken-Domain-VCenter'
$user = 'svc-vmops@vsphere.local'
$password = ConvertTo-SecureString 'KJJPMmqtCYfUHQS4EWUE' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $password)
Connect-VIServer -Server $server -Credential $credential
Get-VM | Select-Object Name, PowerState
