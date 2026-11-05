## Geschichte

Legen Sie Dokumentation zum Verzeichnis und zu den Dateifreigaben dort ab, wo ein Angreifer sie sucht. Die Dokumentation einer Domäne verrät einem Angreifer, wo die Dateiserver und die Domänencontroller stehen. Die Dateien `DFS-namespaces.txt` und `Replication-check.txt` und das folgende Skript nennen einen Host, der zu einem DNS-Honeytoken gehört. Wer eine Freigabe öffnet oder einen Befehl ausführt, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen. Die Dateien `Handover.txt` und `Tickets.csv` enthalten keinen Honeytoken. Sie geben der Geschichte eine glaubhafte Umgebung.

- `DFS-namespaces.txt` listet drei Namespaces der Domäne `corp.example.com` und den Dateiserver auf, der sie bedient.
- `Replication-check.txt` ist das Runbook eines Administrators für die Replikation der Domäne. Zwei seiner Befehle nennen einen Domänencontroller.
- Das folgende Skript legt im Verzeichnis ein Computerobjekt an, mit einem DNS-Hostnamen, der zu einem Honeytoken gehört. Den Server gibt es nicht; das Objekt ist der Köder.

## Umsetzung

Jeder Platzhalter in den Dateien und im Skript gehört zu einem Honeytoken:

- `Honeytoken-Domain-FileServer`: „Dateiserver“, in `DFS-namespaces.txt`
- `Honeytoken-Domain-Controller`: „Domänencontroller“, in `Replication-check.txt`
- `Honeytoken-Domain-Computer`: „Computer im Verzeichnis“, im Skript

1. Legen Sie die drei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Benennen Sie die Namespaces in `DFS-namespaces.txt` um, wenn sie nicht zu Ihrer Organisation passen, und ersetzen Sie `Infrastructure team` in `DFS-namespaces.txt`, `Replication-check.txt` und `Handover.txt` durch ein Team, das es gibt.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach der Struktur der Domäne sucht: auf einem Dateiserver, Domänencontroller oder Administrationsserver, in einem Ordner mit Dokumentation der IT oder in den Dokumenten eines Kontos, das nur diesem Zweck dient.
4. Um das Computerobjekt anzulegen, führen Sie das Skript einmal selbst aus, in einer PowerShell-Sitzung mit dem Modul ActiveDirectory und mit einem Konto, das Computerobjekte anlegen darf:

   ```powershell
   Import-Module ActiveDirectory
   New-ADComputer -Name 'fs-archive01' -SamAccountName 'fs-archive01$' -DNSHostName 'Honeytoken-Domain-Computer' -Enabled $true
   ```

5. Das Objekt landet im Container für neue Computer. Verschieben Sie es in die Organisationseinheit Ihrer Server, damit man es dort findet. Bewahren Sie das Skript dort auf, wo die Dokumentation des Verzeichnisses liegt, wenn es gefunden werden soll.
6. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-FileServer`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Dasselbe bewirkt es, `\\Honeytoken-Domain-FileServer\Shared` im Windows-Explorer zu öffnen. Prüfen Sie das Computerobjekt mit `Get-ADComputer -Identity 'fs-archive01' -Properties DNSHostName`.

## Entfernen

Entfernen Sie das Computerobjekt mit `Remove-ADComputer -Identity 'fs-archive01' -Confirm:$false`. Ein Objekt, das bleibt, wird von Inventarscannern gefunden und zeigt weiter auf den Namen eines Honeytokens.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Die Namespaces unter `corp.example.com` werden nicht angelegt. Ein Angreifer, der einen davon öffnet, findet nichts, und es entsteht kein Ereignis.
- Der Controller in `Replication-check.txt` gehört nicht zu Ihrer Domäne. Ein Angreifer, der den Namen mit der Liste der Controller vergleicht, kann ihn ungewöhnlich finden.
- Nur ein Werkzeug, das den DNS-Hostnamen des Computerobjekts auflöst, löst ein Ereignis aus. Welche Werkzeuge das mit welcher Erfassungsmethode tun, hängt vom Werkzeug und seiner Version ab; für BloodHound und PingCastle ist das nicht überprüft.
- Inventar- und Schwachstellenscanner, die das Verzeichnis durchlaufen, können den Namen auflösen und ein Ereignis auslösen. Nehmen Sie das Objekt von ihnen aus.
