# Skripte und Notizen von Windows-Administratoren

Administratoren einer Windows-Domäne halten Skripte und Notizen fest: ein Skript, das eine Freigabe verbindet, ein Notfallblatt für den lokalen Administrator und Notizen zur Sicherung der Gruppenrichtlinien. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## PowerShell-Skript, das eine Freigabe verbindet

Die Datei `Map-Share.ps1` verbindet die Freigabe `ops` auf dem Server `Honeytoken-Domain-Share` mit dem Konto `CORP\svc-ops` und listet die zehn neuesten Dateien. Der Servername gehört zu einem DNS-Honeytoken: Wer das Skript ausführt oder sich mit den Zugangsdaten mit der Freigabe verbindet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends. Das Skript liest nur aus der Freigabe und sendet nichts von dem Rechner, auf dem es läuft.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Skripten von Administratoren sucht: auf einem Administrationsserver, auf einer Dateifreigabe der IT, in einem Ordner mit Skripten im Profil eines Kontos, das nur diesem Zweck dient.
2. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `Mount-Ops.ps1`. Die Endung `.ps1` muss bleiben.
3. Legen Sie sie nicht dort ab, wo eine geplante Aufgabe oder ein Kollege sie ausführt. Jeder Lauf würde den Namen auflösen und ein Event auslösen.
4. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Führen Sie `nslookup Honeytoken-Domain-Share` auf einem Rechner mit Zugang zum Internet aus; das Skript in PowerShell auszuführen wirkt genauso. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Notfallblatt für den lokalen Administrator

Die Datei `Recovery.txt` ist ein Notfallblatt: Sie nennt den Server `Honeytoken-Domain-Host`, das Konto `Administrator` und ein zufälliges Passwort. Der Servername gehört zu einem DNS-Honeytoken: Wer sich über RDP oder WinRM mit dem Server verbindet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Server, und das Passwort gibt es nirgends.

### Datei platzieren

1. Drucken Sie das Blatt aus oder speichern Sie die Datei dort, wo der Notfallzugang aufbewahrt wird: in einem Ordner der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient, neben der Dokumentation der Domänencontroller.
2. Ändern Sie `Contact` auf eine Nummer oder ein Team, das es gibt.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Namen mit `nslookup Honeytoken-Domain-Host` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Notizen zur Sicherung der Gruppenrichtlinien

Die Datei `GPO-Backup.txt` ist eine Notiz eines Administrators über die Sicherungen der Gruppenrichtlinien. Sie nennt die Freigabe `\\Honeytoken-Domain-Share\GPOBackups$` und das Konto `CORP\svc-ops` mit einem zufälligen Passwort. Der Servername gehört zu einem DNS-Honeytoken: Wer die Freigabe öffnet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Server, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Notizen von Administratoren sucht: auf einem Domänencontroller oder Administrationsserver, auf einer Dateifreigabe der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Ändern Sie `Contact` auf ein Team, das es gibt, damit die Notiz jemanden nennt, der wirklich mit Gruppenrichtlinien arbeitet.
3. Halten Sie in den Notizen des Szenarios fest, wo Sie es abgelegt haben.

### Testen

Öffnen Sie `\\Honeytoken-Domain-Share\GPOBackups$` im Windows-Explorer eines Rechners mit Zugang zum Internet, oder lösen Sie den Namen mit `nslookup Honeytoken-Domain-Share` auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- `Map-Share.ps1`: PowerShell speichert das Passwort im Skript als Text, wie viele Skripte von Administratoren. Ein Eindringling, der das Skript auf einem Rechner mit der Ausführungsrichtlinie `Restricted` startet, wird vor der Abfrage gestoppt.
- `GPO-Backup.txt`: Die Notiz hat keinen ausführbaren Inhalt. Ein Event entsteht nur, wenn jemand die Freigabe öffnet.
