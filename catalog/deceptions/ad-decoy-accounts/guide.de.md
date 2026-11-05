## Geschichte

Legen Sie in Ihrem Verzeichnis drei Konten an, nach denen ein Angreifer sucht, wenn er eine Domäne erkundet, und die niemand benutzt: ein Dienstkonto mit SPN, ein Konto ohne Kerberos-Preauthentifizierung und das Konto eines Administrators. Diese Deception wartet nicht auf eine Anfrage an eine URL. Windows hält jede Anfrage für diese Konten im Sicherheitsprotokoll des Domänencontrollers fest, der sie bedient hat, und ein Log-Forwarder auf jedem Controller schickt die passenden Ereignisse per `POST` an die URL eines Honeytokens. Die Konten sind echte Objekte Ihres Verzeichnisses. Die drei Skripte legen sie an, Sie entscheiden, welche Sie ausführen, und eines genügt. Die Namen der Konten unterscheiden sich voneinander und von jedem vorhandenen Konto, und ein Name hat höchstens 20 Zeichen.

## Umsetzung

### Domänencontroller und Log-Forwarder

Die URL des Honeytokens „Log-Eingang eines Domänencontrollers“ lautet `Honeytoken-URL`. Sie steht in der Konfiguration des Forwarders auf dem Domänencontroller und nur dort. Behandeln Sie sie als Geheimnis: Wer sie kennt, kann gefälschte Ereignisse senden.

1. Das Sicherheitsprotokoll gehört dem einzelnen Domänencontroller, eine Anfrage erscheint also nur im Protokoll des Controllers, der sie bedient hat. Jeder Controller braucht einen Forwarder.
2. Geben Sie jedem Controller ein eigenes Honeytoken, damit der Alert sagt, welcher Controller gemeldet hat. Benennen Sie das Honeytoken dieser Deception nach dem ersten Controller. Legen Sie für jeden weiteren Controller ein Honeytoken vom Typ `web_url` an, benannt nach ihm, mit dem Schweregrad „critical“ und denselben Techniken, und ordnen Sie es dem Szenario zu. Ein Forwarder verwendet nur die URL seines eigenen Controllers.
3. Schalten Sie die Überwachungsrichtlinie in der Gruppenrichtlinie der Domänencontroller ein, Kategorie Account Logon: `Audit Kerberos Service Ticket Operations` (Ereignis 4769), `Audit Kerberos Authentication Service` (Ereignisse 4768 und 4771) und `Audit Credential Validation` (Ereignis 4776), jeweils für Erfolg und Fehler. `auditpol /list /subcategory:*` zeigt die Namen der Unterkategorien.
4. Konfigurieren Sie den Forwarder so, dass er nur die folgenden Ereignisse sendet, und nur für die Konten dieser Deception. Die Beispielkonfiguration und ihre Erklärung stehen in der Dokumentation für Betreiber (docs.nyktus.org), nicht hier. Das Volumen der Kerberos-Ereignisse ist auf einem Domänencontroller sehr hoch, der Forwarder muss also filtern.

Die Ereignisse und die Auswahl des Forwarders je Konto:

- `svc-reporting`: Ereignis 4769, ein Dienstticket wurde angefordert. Der Forwarder wählt die Ereignisse, deren `ServiceName` das Konto ist.
- `svc-legacy-scan`: Ereignis 4768, ein Ticket Granting Ticket wurde angefordert. Der Forwarder wählt die Ereignisse, deren `TargetUserName` das Konto ist. Eine Anfrage ohne Preauthentifizierung hat `PreAuthType` 0.
- `adm-backup`: Ereignisse 4768, 4771 (Preauthentifizierung fehlgeschlagen) und 4776 (Zugangsdaten per NTLM geprüft). Der Forwarder wählt die Ereignisse, deren `TargetUserName` das Konto ist.

### Dienstkonto mit SPN

Das Skript `New-ServiceAccount.ps1` legt das Konto `svc-reporting` mit dem Service Principal Name `MSSQLSvc/sql-reporting01.corp.example.com:1433` und einem zufälligen Passwort an, das es nicht behält. Ein Angreifer, der nach Konten mit SPN sucht und dafür ein Ticket anfordert, um das Passwort offline zu knacken, löst das Ereignis 4769 mit dem Konto als `ServiceName` aus. Niemand hat einen Grund, dieses Ticket anzufordern. Wählen Sie einen Hostnamen, den kein Computer Ihres Verzeichnisses oder DNS benutzt: Ein Name gehört zu einem Konto, und ein echter Server würde seinen Dienstnamen an dieses Konto verlieren.

Das Skript:

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

1. Führen Sie das Skript einmal selbst aus, in einer PowerShell-Sitzung mit dem Modul ActiveDirectory und mit einem Konto, das Benutzer anlegen darf.
2. Verschieben Sie das Konto in die Organisationseinheit Ihrer Dienstkonten, damit man es unter ihnen findet.
3. Bewahren Sie das Skript bei der Dokumentation des Verzeichnisses auf, wenn es gefunden werden soll, oder löschen Sie es.
4. Notieren Sie im Szenario, welches Konto Sie angelegt haben.

### Konto ohne Preauthentifizierung

Das Skript `New-LegacyAccount.ps1` legt das Konto `svc-legacy-scan` mit einem zufälligen Passwort an, das es nicht behält, und stellt ein, dass Kerberos für das Konto keine Preauthentifizierung verlangt. Ein Angreifer, der nach solchen Konten sucht, fordert beim Domänencontroller ein Ticket an, ohne etwas zu belegen, und knackt es offline. Die Anfrage löst das Ereignis 4768 mit `PreAuthType` 0 aus.

Das Skript:

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

1. Führen Sie das Skript einmal selbst aus, in einer PowerShell-Sitzung mit dem Modul ActiveDirectory und mit einem Konto, das Benutzer anlegen und deren Kontooptionen ändern darf.
2. Verschieben Sie das Konto in die Organisationseinheit Ihrer Dienstkonten.
3. Bewahren Sie das Skript bei der Dokumentation des Verzeichnisses auf, wenn es gefunden werden soll, oder löschen Sie es.
4. Notieren Sie im Szenario, welches Konto Sie angelegt haben.

### Administratorkonto, das niemand benutzt

Das Skript `New-AdminAccount.ps1` legt das Konto `adm-backup` mit einem zufälligen Passwort an, das es nicht behält. Das Konto hat keine Rechte: Der Name ist der Köder. Wer Passwörter über die Konten der Domäne sprüht oder gestohlene Zugangsdaten ausprobiert, erreicht es früher oder später. Jeder Versuch löst das Ereignis 4771 (Kerberos, falsches Passwort), 4776 (NTLM) oder 4768 aus, je nachdem, wie er sich authentifiziert. Sie können dem Konto stattdessen den Namen eines ausgeschiedenen Mitarbeiters geben; die Ereignisse sind dieselben.

Niemand, auch Sie nicht, darf sich mit diesem Konto anmelden oder sein Passwort zurücksetzen: Jeder Versuch löst einen Alert aus.

Das Skript:

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

1. Führen Sie das Skript einmal selbst aus, in einer PowerShell-Sitzung mit dem Modul ActiveDirectory und mit einem Konto, das Benutzer anlegen darf.
2. Verschieben Sie das Konto in die Organisationseinheit Ihrer Administratorkonten.
3. Bewahren Sie das Skript bei der Dokumentation des Verzeichnisses auf, wenn es gefunden werden soll, oder löschen Sie es.
4. Notieren Sie im Szenario, welches Konto Sie angelegt haben.

## Testen

Führen Sie den Test eines Kontos auf einem Computer der Domäne aus. Der Domänencontroller, der die Anfrage bedient hat, protokolliert das Ereignis, und sobald der Forwarder es gesendet hat, zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

- `svc-reporting`: Fordern Sie mit `klist get MSSQLSvc/sql-reporting01.corp.example.com:1433` ein Ticket an. Der Controller protokolliert das Ereignis 4769 mit `ServiceName` `svc-reporting`.
- `svc-legacy-scan`: Windows hat keinen Befehl, der ein Ticket ohne Preauthentifizierung anfordert. Führen Sie ein Werkzeug für AS-REP-Roasting von einem Testcomputer aus gegen `svc-legacy-scan` aus, in Absprache mit der Person, die für das Netzwerk verantwortlich ist. Der Controller protokolliert das Ereignis 4768 mit `PreAuthType` 0 und dem Konto als `TargetUserName`. Ohne ein solches Werkzeug können Sie nur mit `Get-ADUser -Identity 'svc-legacy-scan'` prüfen, dass das Konto existiert.
- `adm-backup`: Führen Sie `runas /user:adm-backup@corp.example.com cmd` aus und geben Sie ein beliebiges Passwort ein. Die Anmeldung scheitert, und der Controller, der sie geprüft hat, protokolliert das Ereignis 4771 oder 4776.

## Entfernen

Entfernen Sie ein Konto mit dem Befehl, der zu ihm gehört:

- `Remove-ADUser -Identity 'svc-reporting' -Confirm:$false`
- `Remove-ADUser -Identity 'svc-legacy-scan' -Confirm:$false`
- `Remove-ADUser -Identity 'adm-backup' -Confirm:$false`

Ein Skript hält beim ersten Fehler an. Meldet es einen, nachdem es das Konto angelegt hat, entfernen Sie das Konto mit seinem Befehl, bevor Sie das Skript erneut ausführen. Das gilt vor allem für `New-LegacyAccount.ps1`, das scheitern kann, weil Ihr Konto Kontooptionen nicht ändern darf: Ein Konto, das noch eine Preauthentifizierung verlangt, löst kein Ereignis aus.

## Grenzen

- Es kommen nur Ereignisse eines Domänencontrollers mit Forwarder an. Ein Controller ohne Forwarder oder ohne die Überwachungsrichtlinie oben meldet nichts für die Anfragen, die er bedient, und ein Angreifer kann den Controller wählen.
- Nichts geschieht, wenn ein Angreifer diese Konten nie berührt. Die Deception sieht die Anfragen, die sie nennen, nicht andere Angriffe auf die Domäne.
- Das Honeytoken trägt die Techniken aller drei Konten, und der Alert sagt nicht, welches getroffen wurde. Der Anfang des Bodys sagt es, ist aber nicht Teil des Alerts.
- Die Namen sind für jedes Konto des Verzeichnisses sichtbar. Ein Angreifer, der sie mit den echten Konten vergleicht, kann sie ungewöhnlich finden.
- Das Honeytoken speichert höchstens 10 Ereignisse je Minute, und das erste hat den Alert schon ausgelöst. Der Forwarder sollte seine Ereignisse selbst begrenzen.
- Der Anfang des Bodys, den der Forwarder sendet, bleibt mit dem Ereignis gespeichert, bis zu 4 KiB, und ist nie Teil eines Alerts. Er kann personenbezogene Daten enthalten, etwa Kontonamen und Adressen von Computern, und ist mit der Berechtigung zum Lesen von Ereignissen lesbar.
- Welche Felder der Forwarder liefert, hängt von seiner Konfiguration und seiner Version ab. Prüfen Sie ein echtes Ereignis Ihres Domänencontrollers, bevor Sie sich auf einen Filter verlassen.
- Ein Werkzeug, das die Konten des Verzeichnisses über LDAP auflistet, ohne ein Ticket anzufordern oder sich anzumelden, löst nichts aus.
