## Geschichte

Legen Sie die Zugangsdaten für eine Dateiübertragung dort ab, wo ein Angreifer sie sucht. Administratoren und Entwickler halten sie in den Werkzeugen fest, die sie nutzen: in einer `.netrc`-Datei und im Servermanager von FileZilla. Beide Dateien nennen den Host desselben DNS-Honeytokens, derselbe Hostname steht also in beiden. Wer die Zugangsdaten mit einem Werkzeug verwendet, löst den Namen auf, und das löst ein Ereignis aus. Hinter dem Namen steht kein Server, und Konto und Passwort gibt es nirgends. Eine Datei genügt.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Host“ an. Ersetzen Sie `Honeytoken-Domain` in den Dateien durch seinen Namen.
2. Für `netrc`: Speichern Sie die Datei als `~/.netrc` im Home-Verzeichnis eines Kontos auf einem Server oder Arbeitsplatz, am besten eines Kontos, das nur diesem Zweck dient. Beschränken Sie sie mit `chmod 600 ~/.netrc` auf ihren Besitzer, denn manche Werkzeuge ignorieren eine `.netrc`, die andere lesen können. Hat das Konto bereits eine `~/.netrc`, fügen Sie die drei Zeilen dort an, statt sie zu ersetzen, damit die übrigen Zugangsdaten weiter funktionieren.
3. Für `sitemanager.xml`: Legen Sie die Datei im FileZilla-Verzeichnis eines Kontos auf einem Arbeitsplatz ab, unter Windows `%APPDATA%\FileZilla`. Hat das Konto bereits einen Servermanager, fügen Sie das Element `Server` in dessen `Servers` ein, statt die Datei zu ersetzen.
4. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup Honeytoken-Domain` mit dem Namen des Honeytokens aus. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Um mit dem Werkzeug zu testen, führen Sie `curl --netrc https://Honeytoken-Domain/` aus oder öffnen Sie `sitemanager.xml` in FileZilla und verbinden Sie sich mit dem Eintrag.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Der Hostname ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann ihn ungewöhnlich finden.
- Das Lesen einer Datei löst kein Ereignis aus; die Verbindung zum Eintrag oder die Verwendung der Zugangsdaten tut es.
- `sitemanager.xml`: FileZilla selbst schreibt das Passwort als Base64. Die Datei enthält es als Klartext, was ein Angreifer, der das Format kennt, ungewöhnlich finden kann.
