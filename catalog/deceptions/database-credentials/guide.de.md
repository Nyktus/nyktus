## Geschichte

Legen Sie die Konfiguration einer Anwendung dort ab, wo ein Angreifer nach Zugangsdaten sucht. Die Konfiguration enthält, wie die Anwendung ihre Datenbank und ihr Verzeichnis erreicht. Jeder Dienst hat einen Hostnamen, der zu einem DNS-Honeytoken gehört. Ein Client, der sich mit diesen Werten verbindet, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts, die Verbindungen scheitern also, und Konten, Token und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Database`: „Datenbank-Host“, in `config.ini`, `production.env`, `pgpass` und `my.cnf`
- `Honeytoken-Domain-Directory`: „Verzeichnisserver“, in `ldap.ini`

1. Legen Sie die zwei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Passen Sie die Datenbank `billing`, das Konto `billing_app` und die Passwörter an Ihre Umgebung an.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Zugangsdaten von Anwendungen sucht, Datei für Datei.
4. `config.ini`, `ldap.ini`: neben einer Anwendung auf einem Server, in einem Konfigurations-Repository, in einem Bereitstellungsverzeichnis oder in einer Sicherung davon. Benennen Sie sie um, wenn der Ort einen anderen Namen nahelegt, etwa `database.ini`.
5. `production.env`: in einem Repository eines Dienstes, in einem Bereitstellungsverzeichnis auf einem Server oder in einer Sicherung davon. Benennen Sie sie in `.env` um oder in den Namen, den Ihre Bereitstellungen verwenden. Der Katalog kann keine Datei mit einem Punkt am Anfang benennen.
6. `pgpass`, `my.cnf`: als `.pgpass` und `.my.cnf` im Home-Verzeichnis eines Kontos auf einem Anwendungs- oder Administrationsserver. Wählen Sie die Datei, die zum vorgetäuschten Datenbanksystem passt, oder legen Sie beide ab. Beschränken Sie jede Datei, die Sie ablegen, auf ihren Besitzer, zum Beispiel mit `chmod 600 ~/.pgpass`, denn libpq ignoriert eine `.pgpass`, die andere lesen können.
7. Legen Sie die Dateien nicht dort ab, wo eine laufende Anwendung oder ein Dienst sie liest, und nicht im Konto eines Dienstes, der sich mit einer echten Datenbank verbindet. Die Anwendung würde den Namen bei jedem Start auflösen und Ereignisse auslösen.
8. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Database`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Ein Client hat dieselbe Wirkung und scheitert nach der Abfrage, zum Beispiel `psql` oder `mysql` mit der Datei am Platz.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Das Lesen einer Datei löst kein Ereignis aus; die Verbindung mit ihren Werten tut es.
