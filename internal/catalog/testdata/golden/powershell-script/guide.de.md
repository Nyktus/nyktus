# PowerShell-Skript, das eine Freigabe verbindet

Die Datei `Map-Share.ps1` verbindet die Freigabe `ops` auf dem Server `shareq3xwz7a2kfm4ub6tyc5nre.d.example.net` mit dem Konto `CORP\svc-ops` und listet die zehn neuesten Dateien. Der Servername gehört zu einem DNS-Honeytoken: Wer das Skript ausführt oder sich mit den Zugangsdaten mit der Freigabe verbindet, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends. Das Skript liest nur aus der Freigabe und sendet nichts von dem Rechner, auf dem es läuft.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Skripten von Administratoren sucht: auf einem Administrationsserver, auf einer Dateifreigabe der IT, in einem Ordner mit Skripten im Profil eines Kontos, das nur diesem Zweck dient.
2. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `Mount-Ops.ps1`. Die Endung `.ps1` muss bleiben.
3. Legen Sie sie nicht dort ab, wo eine geplante Aufgabe oder ein Kollege sie ausführt. Jeder Lauf würde den Namen auflösen und ein Event auslösen.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Führen Sie `nslookup shareq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet aus; das Skript in PowerShell auszuführen wirkt genauso. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Servername ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
- PowerShell speichert das Passwort im Skript als Text, wie viele Skripte von Administratoren. Ein Eindringling, der das Skript auf einem Rechner mit der Ausführungsrichtlinie `Restricted` startet, wird vor der Abfrage gestoppt.
