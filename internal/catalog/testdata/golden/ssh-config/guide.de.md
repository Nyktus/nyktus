# SSH-Konfiguration mit Jump-Host

Die Datei `config` ist eine SSH-Client-Konfiguration. Sie leitet jede Verbindung zu einem Host unter `corp.example.com` und jede Verbindung zu `jump` über den Jump-Host `jumphostq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Dieser Name gehört zu einem DNS-Honeytoken: Bevor SSH sich verbindet, löst es den Namen auf, und die Abfrage löst ein Event aus. Die Verbindung selbst scheitert, weil hinter dem Namen kein SSH-Server steht.

## Datei platzieren

1. Legen Sie die Datei dort ab, wo ein Eindringling nach Zugängen zu weiteren Hosts sucht, zum Beispiel als `~/.ssh/config` eines Kontos auf einem Jump-Server oder einem Administrationsrechner, oder auf einer Dateifreigabe zwischen Skripten und Notizen der IT.
2. Auf einem System, auf dem die Datei als `~/.ssh/config` dient, beschränken Sie sie auf ihren Besitzer: `chmod 600 ~/.ssh/config`. SSH verweigert Konfigurationsdateien, die andere beschreiben können.
3. Legen Sie sie nicht dort ab, wo Kollegen sie für ihre eigene Arbeit nutzen. Jedes legitime `ssh` zu einem Host unter `corp.example.com` würde ein Event auslösen.
4. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben, damit es wiedergefunden und entfernt werden kann.

## Testen

Führen Sie `ssh -F config jump` auf einem Rechner aus, der Namen über das Internet auflöst. Innerhalb einer Minute zeigt das Scenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Name des Jump-Hosts ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
