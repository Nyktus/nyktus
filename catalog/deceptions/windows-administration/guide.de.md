## Geschichte

Legen Sie Skripte und Notizen von Windows-Administratoren dort ab, wo ein Angreifer sie sucht. Administratoren einer Windows-Domäne halten ein Skript fest, das eine Freigabe verbindet, ein Notfallblatt für den lokalen Administrator und Notizen zur Sicherung von Gruppenrichtlinien. Jede Datei nennt einen Server, der zu einem DNS-Honeytoken gehört. Wer das Skript ausführt oder die Zugangsdaten verwendet, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts, Verbindungen scheitern also, und Konten und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Share`: „Dateiserver“, in `Map-Share.ps1` und `GPO-Backup.txt`
- `Honeytoken-Domain-Host`: „Server“, in `Recovery.txt`

1. Legen Sie die zwei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Ändern Sie in `Recovery.txt` und `GPO-Backup.txt` die Zeile `Contact` auf ein Team oder eine Nummer, die es gibt, damit die Notiz jemanden nennt, der sich mit dem Thema befasst.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Notizen und Skripten von Administratoren sucht: auf einem Administrationsserver oder Domänencontroller, auf einer Dateifreigabe der IT, neben der Dokumentation der Domänencontroller oder im Profil eines Kontos, das nur diesem Zweck dient. Drucken Sie `Recovery.txt` aus, wenn der Notfallzugang auf Papier aufbewahrt wird.
4. Benennen Sie `Map-Share.ps1` um, wenn der Ort einen anderen Namen nahelegt, etwa `Mount-Ops.ps1`. Die Endung `.ps1` muss bleiben.
5. Legen Sie `Map-Share.ps1` nicht dort ab, wo eine geplante Aufgabe oder ein Kollege es ausführt. Jeder Lauf würde den Namen auflösen und ein Ereignis auslösen.
6. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Share`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Dasselbe bewirkt es, das Skript in PowerShell auszuführen oder die Freigabe `\\Honeytoken-Domain-Share\GPOBackups$` im Windows-Explorer zu öffnen.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- `Map-Share.ps1` enthält das Passwort als Text, wie viele Skripte von Administratoren, und liest nur von der Freigabe. Ein Angreifer, der es auf einem Rechner mit der Ausführungsrichtlinie `Restricted` ausführt, wird vor der Abfrage gestoppt.
- `GPO-Backup.txt` enthält nichts Ausführbares. Ein Ereignis entsteht erst, wenn jemand die Freigabe öffnet.
