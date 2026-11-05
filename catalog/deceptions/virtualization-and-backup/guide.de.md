## Geschichte

Legen Sie den Zugang zur Virtualisierungsplattform und zum Sicherungsrepository dort ab, wo ein Angreifer ihn sucht. Wer diesen Zugang hat, kann die Maschinen und ihre Sicherungen lesen oder löschen, er gehört also zu den wertvollsten, die ein Angreifer finden kann. Zwei Dateien enthalten ihn: ein PowerShell-Skript, das sich mit einem vCenter-Server verbindet, und eine Notiz über das Sicherungsrepository. Jede nennt einen Server, der zu einem DNS-Honeytoken gehört. Wer die Zugangsdaten verwendet, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts, und Konten und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-VCenter`: „vCenter-Server“, in `Connect-VCenter.ps1`
- `Honeytoken-Domain-Repository`: „Repository-Server“, in `Backup-repository.txt`

1. Legen Sie die zwei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Ändern Sie in `Backup-repository.txt` die Zeile `Contact` auf ein Team, das es gibt.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Zugang zur Virtualisierung oder zu den Sicherungen sucht: auf einem Administrationsserver, auf dem Sicherungsserver, auf einer Dateifreigabe der IT oder in einem Ordner mit Skripten im Profil eines Kontos, das nur diesem Zweck dient.
4. Legen Sie `Connect-VCenter.ps1` nicht dort ab, wo eine geplante Aufgabe oder ein Kollege es ausführt.
5. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-VCenter`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Dasselbe bewirkt es, die Freigabe im Windows-Explorer zu öffnen oder das Skript mit VMware PowerCLI auszuführen.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- `Connect-VCenter.ps1` braucht VMware PowerCLI. Fehlt es, scheitert das Skript vor der Abfrage. Das Skript liest nur und sendet nichts vom Rechner, auf dem es läuft.
