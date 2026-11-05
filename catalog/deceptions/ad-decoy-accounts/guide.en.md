## Story

Add three accounts to your directory that an intruder looks for when exploring a domain and that nobody uses: a service account with an SPN, an account without Kerberos preauthentication and the account of an administrator. This deception does not wait for a request to a URL. Windows records every request for these accounts in the Security log of the domain controller that served it, and a log forwarder on each controller sends the matching events by `POST` to the URL of a honeytoken. The accounts are real objects of your directory. The three scripts create them, you decide which ones to run, and one is enough. The names of the accounts differ from each other and from every account that exists, and a name has up to 20 characters.

## Setup

### Domain controllers and the log forwarder

The URL of the honeytoken "Log ingest of a domain controller" is `Honeytoken-URL`. It stands in the configuration of the forwarder on the domain controller and is the only place that needs it. Treat it as a secret: whoever knows it can send forged events.

1. The Security log belongs to each domain controller, so a request appears only in the log of the controller that served it. Every controller needs a forwarder.
2. Give every controller a honeytoken of its own, so that the alert says which controller reported. Name the honeytoken of this deception after the first controller. For every further controller, create a honeytoken of the type `web_url` named after it, with the severity critical and the same techniques, and assign it to the scenario. A forwarder uses the URL of its own controller only.
3. Turn on the audit policy in the group policy of the domain controllers, category Account Logon: `Audit Kerberos Service Ticket Operations` (event 4769), `Audit Kerberos Authentication Service` (events 4768 and 4771) and `Audit Credential Validation` (event 4776), each for success and failure. `auditpol /list /subcategory:*` shows the names of the subcategories.
4. Configure the forwarder to send only the events below, and only for the accounts of this deception. The example configuration and its explanation are in the operator documentation (docs.nyktus.org), not here. The volume of the Kerberos events is very high on a domain controller, so the forwarder must filter.

The events and what the forwarder selects for each account:

- `svc-reporting`: event 4769, a service ticket was requested. The forwarder selects the events whose `ServiceName` is the account.
- `svc-legacy-scan`: event 4768, a ticket granting ticket was requested. The forwarder selects the events whose `TargetUserName` is the account. A request without preauthentication has `PreAuthType` 0.
- `adm-backup`: events 4768, 4771 (preauthentication failed) and 4776 (credentials checked with NTLM). The forwarder selects the events whose `TargetUserName` is the account.

### Service account with an SPN

The script `New-ServiceAccount.ps1` creates the account `svc-reporting` with the service principal name `MSSQLSvc/sql-reporting01.corp.example.com:1433` and a random password that it does not keep. An intruder who looks for accounts with an SPN and asks for a ticket for it, to crack the password offline, raises event 4769 with the account as `ServiceName`. Nobody has a reason to ask for this ticket. Choose a host name that no computer of your directory or DNS uses: a name belongs to one account, and a real server would lose its service name to this one.

The script:

```powershell
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$bytes = New-Object byte[] 48
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$generator.GetBytes($bytes)
$generator.Dispose()
$plain = [Convert]::ToBase64String($bytes) + 'aA1!'
$password = ConvertTo-SecureString $plain -AsPlainText -Force
New-ADUser -Name 'svc-reporting' -SamAccountName 'svc-reporting' -UserPrincipalName 'svc-reporting@corp.example.com' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true -ServicePrincipalNames 'MSSQLSvc/sql-reporting01.corp.example.com:1433'
```

1. Run the script once yourself, in a PowerShell session with the ActiveDirectory module and an account that may create users.
2. Move the account to the organizational unit of your service accounts, so that it is found among them.
3. Keep the script where the documentation of the directory is, if you want it to be found, or delete it.
4. Record in the notes of the scenario which account you created.

### Account without preauthentication

The script `New-LegacyAccount.ps1` creates the account `svc-legacy-scan` with a random password that it does not keep, and sets that Kerberos does not require preauthentication for it. An intruder who looks for such accounts asks the domain controller for a ticket without proving anything and cracks it offline. The request raises event 4768 with `PreAuthType` 0.

The script:

```powershell
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
```

1. Run the script once yourself, in a PowerShell session with the ActiveDirectory module and an account that may create users and change their account options.
2. Move the account to the organizational unit of your service accounts.
3. Keep the script where the documentation of the directory is, if you want it to be found, or delete it.
4. Record in the notes of the scenario which account you created.

### Administrator account that nobody uses

The script `New-AdminAccount.ps1` creates the account `adm-backup` with a random password that it does not keep. The account holds no rights: it is the name that is the bait. Whoever sprays passwords over the accounts of the domain or tries credentials that they stole reaches it sooner or later, and every attempt raises event 4771 (Kerberos, wrong password), 4776 (NTLM) or 4768, depending on how the attempt authenticates. You can give the account the name of an employee who has left instead; the events are the same.

Nobody, you included, may sign in as this account or reset its password: every attempt is an alert.

The script:

```powershell
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$bytes = New-Object byte[] 48
$generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$generator.GetBytes($bytes)
$generator.Dispose()
$plain = [Convert]::ToBase64String($bytes) + 'aA1!'
$password = ConvertTo-SecureString $plain -AsPlainText -Force
New-ADUser -Name 'adm-backup' -SamAccountName 'adm-backup' -UserPrincipalName 'adm-backup@corp.example.com' -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
```

1. Run the script once yourself, in a PowerShell session with the ActiveDirectory module and an account that may create users.
2. Move the account to the organizational unit of your administrator accounts.
3. Keep the script where the documentation of the directory is, if you want it to be found, or delete it.
4. Record in the notes of the scenario which account you created.

## Testing

Run the test of an account on a computer of the domain. The domain controller that served the request logs the event, and once the forwarder has sent it, the scenario shows an incident. Close the incident after the test.

- `svc-reporting`: request a ticket with `klist get MSSQLSvc/sql-reporting01.corp.example.com:1433`. The controller logs event 4769 with `ServiceName` `svc-reporting`.
- `svc-legacy-scan`: Windows has no command that asks for a ticket without preauthentication. Run a tool for AS-REP roasting against `svc-legacy-scan` from a test computer, in agreement with whoever is responsible for the network. The controller logs event 4768 with `PreAuthType` 0 and the account as `TargetUserName`. Without such a tool you can only check that the account exists with `Get-ADUser -Identity 'svc-legacy-scan'`.
- `adm-backup`: run `runas /user:adm-backup@corp.example.com cmd` and enter any password. The sign-in fails, and the controller that checked it logs event 4771 or 4776.

## Removing

Remove an account with the command that belongs to it:

- `Remove-ADUser -Identity 'svc-reporting' -Confirm:$false`
- `Remove-ADUser -Identity 'svc-legacy-scan' -Confirm:$false`
- `Remove-ADUser -Identity 'adm-backup' -Confirm:$false`

A script stops at its first error. If it reports one after it created the account, remove the account with its command before you run the script again. This matters most for `New-LegacyAccount.ps1`, which can fail because your account may not change account options: an account that still requires preauthentication raises no event.

## Limits

- Only events of a domain controller with a forwarder arrive. A controller without one, or without the audit policy above, reports nothing for the requests it serves, and an intruder can choose the controller.
- Nothing happens when an intruder never touches these accounts. The deception sees the requests that name them, not other attacks on the domain.
- The honeytoken carries the techniques of all three accounts, and the alert does not say which one was hit. The start of the body does, but it is not part of the alert.
- The names are visible to every account of the directory. An intruder who compares them with the real accounts can find them unusual.
- The honeytoken stores at most 10 events per minute, and the first one has already raised the alert. The forwarder should limit its events itself.
- The start of the body that the forwarder sends is kept with the event, up to 4 KiB, and is never part of an alert. It can hold personal data, such as account names and addresses of computers, and is read with the permission to read events.
- Which fields the forwarder delivers depends on its configuration and its version. Check a real event of your domain controller before you rely on a filter.
- A tool that lists the accounts of the directory over LDAP without asking for a ticket or signing in raises nothing.
