## Geschichte

Legen Sie Zugänge, die Entwickler hinterlassen, dort ab, wo ein Angreifer sie sucht. Entwickler hinterlassen den Zugang zu internen Diensten in ihren Werkzeugen: eine Notiz mit einem API-Aufruf, die Zugangsdaten des Git-Servers und die Konfiguration der Paketmanager. Jeder Dienst hat einen Hostnamen, der zu einem DNS-Honeytoken gehört. Wer den Zugang verwendet, löst den Namen auf, und das löst ein Ereignis aus. Hinter den Namen steht nichts, die Aufrufe scheitern also, und Konten, Token und Passwörter gibt es nirgends. Eine Datei genügt, und die Dateien müssen nicht beieinander liegen. Die Datei `README.md` enthält keinen Honeytoken. Sie gibt der Geschichte eine glaubhafte Umgebung.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Api`: „API-Host“, in `api-call.txt`
- `Honeytoken-Domain-Git`: „Git-Server“, in `git-credentials` und `config`
- `Honeytoken-Domain-Registry`: „Paket-Registry“, in `npmrc` und `pip.conf`

1. Legen Sie die drei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Ersetzen Sie in `api-call.txt` den Dienst `Inventory service` durch einen Dienst, den Ihre Organisation hat, damit die Notiz zu ihrer Umgebung passt.
3. Legen Sie die Dateien dort ab, wo ein Angreifer nach Zugängen von Entwicklern sucht, Datei für Datei.
4. `api-call.txt`: dort, wo Administratoren Befehle für später hinterlassen, etwa in den Notizen eines Kontos auf einem Server, in einem Ordner mit Skripten oder in einem Wiki-Export.
5. `git-credentials`: als `.git-credentials` im Home-Verzeichnis eines Kontos auf einem Arbeitsplatz oder Build-Server. Git liest sie nur, wenn `credential.helper` auf `store` steht.
6. `config`: als `.git/config` in einem Verzeichnis mit der Kopie eines Repositorys, etwa einem Checkout auf einem Build-Server oder einer Sicherung davon.
7. `npmrc`: als `.npmrc` im Home-Verzeichnis eines Kontos auf einem Arbeitsplatz oder Build-Server oder im Hauptverzeichnis eines Projekts.
8. `pip.conf`: als `~/.config/pip/pip.conf` im Home-Verzeichnis eines Kontos.
9. `README.md`: neben den anderen Dateien der Geschichte.
10. Legen Sie `config`, `npmrc` und `pip.conf` nicht dort ab, wo jemand mit Git, npm oder pip arbeitet oder wo ein Build sie ausführt. Jedes `git fetch`, `npm install` oder `pip install` würde den Namen auflösen und ein Ereignis auslösen.
11. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Registry`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Die Werkzeuge haben dieselbe Wirkung und scheitern nach der Abfrage: `git ls-remote https://Honeytoken-Domain-Git/platform-prod.git` mit Git oder `npm install` in einem Verzeichnis mit `.npmrc`.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Das Lesen einer Datei löst kein Ereignis aus; die Verwendung des Zugangs tut es.
