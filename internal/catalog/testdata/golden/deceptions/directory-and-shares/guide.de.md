# Dokumentation von Verzeichnis und Dateifreigaben

Die Dokumentation einer Domäne verrät einem Eindringling, wo Dateiserver und Domänencontroller stehen. Die folgenden Dateien sind solche Dokumentation. Die Dateien teilen sich die Honeytokens der Geschichte, derselbe Host-Name steht also in jeder Datei, die denselben Dienst nennt. Hinter den Namen steht nichts: Konten, Token und Passwörter gibt es nirgends. Sie entscheiden, welche Dateien Sie wo ablegen; eine genügt, und sie müssen nicht beieinander liegen.

## Übersicht der DFS-Namespaces

Die Datei `DFS-namespaces.txt` listet drei Namespaces der Domain `corp.example.com` und den Dateiserver `fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf, der sie bedient. Der Servername gehört zu einem DNS-Honeytoken: Wer eines der Ziele öffnet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Dateiserver.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Freigaben sucht: auf einem Dateiserver oder Administrationsserver, in einem Ordner mit Dokumentation der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Benennen Sie die Namespaces um, wenn sie nicht zu Ihrer Organisation passen, und ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Öffnen Sie `\\fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net\Shared` im Windows-Explorer eines Rechners mit Zugang zum Internet, oder lösen Sie den Namen mit `nslookup fileserverq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Runbook zur Prüfung der Replikation

Die Datei `Replication-check.txt` ist ein Runbook eines Administrators für die Replikation der Domain `corp.example.com`. Zwei seiner Befehle nennen den Domänencontroller `controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Der Name gehört zu einem DNS-Honeytoken: Wer einen der Befehle ausführt, löst ihn auf, was ein Event auslöst. Dahinter steht kein Controller.

### Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach der Struktur der Domain sucht: auf einem Domänencontroller oder Administrationsserver, auf einer Dateifreigabe der IT, in den Dokumenten eines Kontos, das nur diesem Zweck dient.
2. Ändern Sie `Contact` auf ein Team, das es gibt.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Namen mit `nslookup controllerq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- `DFS-namespaces.txt`: Die Namespaces unter `corp.example.com` werden nicht angelegt. Ein Eindringling, der einen davon öffnet, findet nichts, und es entsteht kein Event.
- `Replication-check.txt`: Der Controller gehört nicht zu Ihrer Domain. Ein Eindringling, der den Namen mit der Liste der Controller vergleicht, kann ihn ungewöhnlich finden.
