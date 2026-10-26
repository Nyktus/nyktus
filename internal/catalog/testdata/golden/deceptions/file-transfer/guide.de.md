# Zugang zur Dateiübertragung

Administratoren und Entwickler halten die Zugangsdaten für Dateiübertragungen in den Werkzeugen fest, die sie benutzen: in einer `.netrc`-Datei und im Servermanager von FileZilla. Die folgenden Dateien erzählen diese Geschichte an verschiedenen Orten. Die Dateien teilen sich den Honeytoken der Geschichte, derselbe Host-Name steht also in beiden. Hinter dem Namen steht nichts: Konto und Passwort gibt es nirgends. Sie entscheiden, welche Datei Sie wo ablegen; eine genügt.

## Zugangsdaten in einer .netrc-Datei

Die Datei `netrc` enthält das Konto `deploy` und ein zufälliges Passwort für den Host `hostq3xwz7a2kfm4ub6tyc5nre.d.example.net`. Werkzeuge wie curl, Git, ftp und viele Skripte lesen solche Zugangsdaten aus `~/.netrc`. Der Host-Name gehört zu einem DNS-Honeytoken: Wer die Zugangsdaten mit irgendeinem Werkzeug nutzt, löst den Namen auf, was ein Event auslöst. Dahinter steht kein Server, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Speichern Sie die Datei als `~/.netrc` im Home-Verzeichnis eines Kontos auf einem Server oder Arbeitsplatz, am besten eines Kontos, das nur diesem Zweck dient, und beschränken Sie sie auf ihren Besitzer: `chmod 600 ~/.netrc`. Manche Werkzeuge ignorieren eine `.netrc`, die andere lesen können.
2. Hat das Konto schon eine `~/.netrc`, ergänzen Sie diese um die drei Zeilen, statt sie zu ersetzen, damit seine übrigen Zugangsdaten weiter funktionieren.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Führen Sie `curl --netrc https://hostq3xwz7a2kfm4ub6tyc5nre.d.example.net/` auf einem Rechner mit Zugang zum Internet aus. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## FileZilla-Servermanager

Die Datei `sitemanager.xml` ist der Servermanager von FileZilla mit dem Server `hostq3xwz7a2kfm4ub6tyc5nre.d.example.net`, dem Konto `deploy` und einem zufälligen Passwort. Der Host-Name gehört zu einem DNS-Honeytoken: Wer sich mit dem Eintrag verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Server, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Legen Sie die Datei als `sitemanager.xml` im FileZilla-Verzeichnis eines Kontos auf einem Arbeitsplatz ab (unter Windows `%APPDATA%\FileZilla`).
2. Hat das Konto schon einen Servermanager, ergänzen Sie dessen `Servers` um das Element `Server`, statt die Datei zu ersetzen.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Host mit `nslookup hostq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet auf, oder öffnen Sie die Datei in FileZilla und verbinden Sie sich mit dem Eintrag. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Der Host-Name ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Datei genau liest, kann ihn ungewöhnlich finden.
- `sitemanager.xml`: FileZilla schreibt das Passwort selbst als Base64. Die Datei enthält das Secret als Klartext, was ein Eindringling, der das Format kennt, ungewöhnlich finden kann.
- `sitemanager.xml`: Das Öffnen der Datei in FileZilla löst kein Event aus; erst die Verbindung mit dem Eintrag tut es.
