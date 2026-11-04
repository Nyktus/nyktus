# Dokumentation von Verzeichnis und Dateifreigaben

Die Dokumentation einer Domäne verrät einem Eindringling, wo Dateiserver und Domänencontroller stehen. Die folgenden Dateien sind solche Dokumentation. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## Übersicht der DFS-Namespaces

Die Datei `DFS-namespaces.txt` listet drei Namespaces der Domain `corp.example.com` und den Dateiserver `Honeytoken-Domain-FileServer` auf, der sie bedient. Der Servername gehört zu einem DNS-Honeytoken: Wer eines der Ziele öffnet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Dateiserver.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Freigaben sucht: auf einem Dateiserver oder Administrationsserver, in einem Ordner mit Dokumentation der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Benennen Sie die Namespaces um, wenn sie nicht zu Ihrer Organisation passen, und ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Öffnen Sie `\\Honeytoken-Domain-FileServer\Shared` im Windows-Explorer eines Rechners mit Zugang zum Internet, oder lösen Sie den Namen mit `nslookup Honeytoken-Domain-FileServer` auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Runbook zur Prüfung der Replikation

Die Datei `Replication-check.txt` ist ein Runbook eines Administrators für die Replikation der Domain `corp.example.com`. Zwei seiner Befehle nennen den Domänencontroller `Honeytoken-Domain-Controller`. Der Name gehört zu einem DNS-Honeytoken: Wer einen der Befehle ausführt, löst ihn auf, was ein Event auslöst. Dahinter steht kein Controller.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach der Struktur der Domain sucht: auf einem Domänencontroller oder Administrationsserver, auf einer Dateifreigabe der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Namen mit `nslookup Honeytoken-Domain-Controller` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Computerobjekt im Verzeichnis

Das Skript `New-ServerObject.ps1` legt das Computerobjekt `fs-archive01` im Verzeichnis an, mit dem DNS-Hostnamen `Honeytoken-Domain-Computer`. Der Hostname gehört zu einem DNS-Honeytoken: Ein Werkzeug, das sich per DNS-Namen mit den Computern der Domäne verbindet, löst ihn auf, was ein Event auslöst. Den Server gibt es nicht; der Köder ist das Objekt, und die Datei legt es nur an, wenn jemand sie ausführt.

Das Skript:

```powershell
Import-Module ActiveDirectory
New-ADComputer -Name 'fs-archive01' -SamAccountName 'fs-archive01$' -DNSHostName 'Honeytoken-Domain-Computer' -Enabled $true
```

### Datei platzieren

1. Führen Sie das Skript einmal selbst aus, in einer PowerShell-Sitzung mit dem Modul ActiveDirectory und mit einem Konto, das Computerobjekte anlegen darf.
2. Das Objekt landet im Container für neue Computer. Verschieben Sie es in die Organisationseinheit Ihrer Server, damit es dort gefunden wird.
3. Bewahren Sie das Skript bei der Dokumentation des Verzeichnisses auf, wenn es gefunden werden soll.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Prüfen Sie das Objekt mit `Get-ADComputer -Identity 'fs-archive01' -Properties DNSHostName`, und lösen Sie dann den Hostnamen mit `nslookup Honeytoken-Domain-Computer` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Pocket Litter

Die Dateien `Handover.txt` und `Tickets.csv` enthalten keinen Honeytoken und lösen kein Event aus, was auch mit ihnen geschieht. Sie geben der Geschichte eine glaubhafte Umgebung: Legen Sie sie an denselben Orten ab wie die übrigen Dateien der Geschichte, neben den Dateien, die ein Event auslösen.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- `DFS-namespaces.txt`: Die Namespaces unter `corp.example.com` werden nicht angelegt. Ein Eindringling, der einen davon öffnet, findet nichts, und es entsteht kein Event.
- `Replication-check.txt`: Der Controller gehört nicht zu Ihrer Domain. Ein Eindringling, der den Namen mit der Liste der Controller vergleicht, kann ihn ungewöhnlich finden.
- `New-ServerObject.ps1`: Nur ein Werkzeug, das den DNS-Hostnamen des Objekts auflöst, löst ein Event aus. Welche Werkzeuge das tun und mit welcher Erfassungsmethode, hängt vom Werkzeug und seiner Version ab; für BloodHound und PingCastle ist es nicht geprüft.
- `New-ServerObject.ps1`: Inventar- und Schwachstellenscanner, die das Verzeichnis durchlaufen, können den Namen auflösen und ein Event auslösen. Nehmen Sie das Objekt von ihnen aus.
