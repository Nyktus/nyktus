# Zugang zu Virtualisierung und Sicherung

Der Zugang zur Virtualisierungsplattform und zum Sicherungs-Repository gehört zu den wertvollsten, die ein Eindringling finden kann, denn wer ihn hat, kann die Maschinen und ihre Sicherungen lesen oder löschen. Die folgenden Dateien halten ihn fest. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## PowerShell-Profil für vCenter

Die Datei `Connect-VCenter.ps1` verbindet sich mit dem vCenter-Server `Honeytoken-Domain-VCenter` mit dem Konto `svc-vmops@vsphere.local` und listet die virtuellen Maschinen. Der Name des Servers gehört zu einem DNS-Honeytoken: Wer das Skript ausführt oder sich mit den Zugangsdaten mit dem Server verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends. Das Skript liest nur und sendet nichts von dem Rechner, auf dem es läuft.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugang zur Virtualisierung sucht: auf einem Administrationsserver, auf einer Dateifreigabe der IT, in einem Ordner mit Skripten im Profil eines Kontos, das nur diesem Zweck dient.
2. Legen Sie sie nicht dort ab, wo eine geplante Aufgabe oder ein Kollege sie ausführt.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Führen Sie `nslookup Honeytoken-Domain-VCenter` auf einem Rechner mit Zugang zum Internet aus; das Skript mit VMware PowerCLI auszuführen wirkt genauso. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Notizen zum Sicherungs-Repository

Die Datei `Backup-repository.txt` ist eine Notiz eines Administrators über das Repository der Sicherungen. Sie nennt die Freigabe `\\Honeytoken-Domain-Repository\Repository` und das Konto `CORP\svc-vmops` mit einem zufälligen Passwort. Der Servername gehört zu einem DNS-Honeytoken: Wer die Freigabe öffnet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Server, und Konto und Passwort gibt es nirgends. Eindringlinge, die Ransomware vorbereiten, suchen genau danach.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach den Sicherungen sucht: auf dem Sicherungsserver, auf einem Administrationsserver, auf einer Dateifreigabe der IT.
2. Ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Öffnen Sie `\\Honeytoken-Domain-Repository\Repository` im Windows-Explorer eines Rechners mit Zugang zum Internet, oder lösen Sie den Namen mit `nslookup Honeytoken-Domain-Repository` auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- `Connect-VCenter.ps1`: Das Skript braucht VMware PowerCLI. Wo es fehlt, scheitert das Skript vor der Abfrage.
