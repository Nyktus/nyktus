# PowerShell-Profil für vCenter

Die Datei `Connect-VCenter.ps1` verbindet sich mit dem vCenter-Server `vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` mit dem Konto `svc-vmops@vsphere.local` und listet die virtuellen Maschinen. Der Name des Servers gehört zu einem DNS-Honeytoken: Wer das Skript ausführt oder sich mit den Zugangsdaten mit dem Server verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Server, die Verbindung scheitert also, und Konto und Passwort gibt es nirgends. Das Skript liest nur und sendet nichts von dem Rechner, auf dem es läuft.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugang zur Virtualisierung sucht: auf einem Administrationsserver, auf einer Dateifreigabe der IT, in einem Ordner mit Skripten im Profil eines Kontos, das nur diesem Zweck dient.
2. Legen Sie sie nicht dort ab, wo eine geplante Aufgabe oder ein Kollege sie ausführt.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

## Testen

Führen Sie `nslookup vcenterq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet aus; das Skript mit VMware PowerCLI auszuführen wirkt genauso. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Name des Servers ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
- Das Skript braucht VMware PowerCLI. Wo es fehlt, scheitert das Skript vor der Abfrage.
