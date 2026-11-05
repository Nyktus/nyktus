## Geschichte

Legen Sie den Verlauf einer Shell dort ab, wo ein Angreifer nach Befehlen sucht, die Administratoren getippt haben. Administratoren und Entwickler lassen ihre Befehle im Verlauf ihrer Shell zurück, samt Passwörtern und Hostnamen. Die Dateien erzählen das für Linux und für Windows. Hinter den Hostnamen steht nichts, und Konten und Passwörter gibt es nirgends. Eine Datei genügt.

- `bash_history` ist der Verlauf einer Linux-Shell. Er enthält den Befehl, der sich mit dem Konto `svc-ops` und einem zufälligen Passwort an der Datenbank `billing` anmeldet.
- `ConsoleHost_history.txt` ist der PSReadLine-Verlauf von PowerShell. Er enthält die Befehle, die die Zugangsdaten des Kontos `CORP\svc-ops` abfragen und eine Remotesitzung zu einem Server öffnen. Er enthält kein Passwort, denn PowerShell schreibt Befehlszeilen mit Passwort, Token oder Secret nicht in seinen Verlauf.

Jeder Hostname gehört zu einem DNS-Honeytoken. Wer einen Befehl ausführt oder sich anderweitig mit dem Host verbindet, löst den Namen auf, und das löst ein Ereignis aus.

## Umsetzung

Jeder Platzhalter in den Dateien gehört zu einem Honeytoken:

- `Honeytoken-Domain-Database`: „Datenbank-Host“, in `bash_history`
- `Honeytoken-Domain-Server`: „Server“, in `ConsoleHost_history.txt`

1. Legen Sie die zwei DNS-Honeytokens an.
2. Ersetzen Sie jeden Platzhalter durch den Namen seines Honeytokens. Passen Sie die Namen von Konten und Datenbanken an Ihre Umgebung an.
3. Für `bash_history`: Benennen Sie die Datei `.bash_history` und legen Sie sie im Home-Verzeichnis eines Kontos auf einem Anwendungsserver ab, an dem Menschen sich anmelden.
4. Für `ConsoleHost_history.txt`: Legen Sie die Datei im Verzeichnis `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine` eines Kontos auf einem Server oder Arbeitsplatz von Administratoren ab.
5. Hat das Konto bereits einen Verlauf, hängen Sie die Zeilen an, statt ihn zu ersetzen. Ein neuer Verlauf, der nichts Älteres als die Köder enthält, wirkt gemacht.
6. Notieren Sie im Szenario, wo die Dateien liegen.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup` mit dem Namen eines Honeytokens aus, zum Beispiel `nslookup Honeytoken-Domain-Database`. Die Namen stehen in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Die Hostnamen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Wer die Dateien genau liest, kann sie ungewöhnlich finden.
- Das Lesen der Dateien löst kein Ereignis aus; die Verwendung der Zugangsdaten oder die Ausführung der Befehle tut es.
