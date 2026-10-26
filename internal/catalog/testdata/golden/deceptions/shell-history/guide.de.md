# Shell-Verlauf mit Befehlen für Server

Administratoren und Entwickler lassen die Befehle, die sie getippt haben, im Verlauf ihrer Shell zurück, samt Passwörtern und Host-Namen. Die folgenden Dateien erzählen diese Geschichte für Linux und für Windows. Die Dateien teilen sich keinen Honeytoken: Datenbank und Server haben eigene Namen. Hinter den Namen steht nichts, und Konten und Passwörter gibt es nirgends. Sie entscheiden, welche Datei Sie wo ablegen; eine genügt.

## Verlauf einer Linux-Shell

Die Datei `bash_history` ist der Verlauf einer Linux-Shell. Sie enthält den Befehl, der sich an der Datenbank `billing` auf `databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net` mit dem Konto `svc-ops` und einem zufälligen Passwort anmeldet. Der Host-Name gehört zu einem DNS-Honeytoken: Wer den Befehl ausführt oder sich sonst mit dem Host verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht keine Datenbank, und Konto und Passwort gibt es nirgends.

### Datei platzieren

1. Nennen Sie die Datei `.bash_history` und legen Sie sie im Home-Verzeichnis eines Kontos auf einem Anwendungsserver ab, an dem sich Personen anmelden.
2. Hat das Konto schon einen Verlauf, hängen Sie die Zeilen an, statt ihn zu ersetzen: Ein neuer Verlauf, in dem nichts älter ist als die Köder, wirkt gemacht.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Host mit `nslookup databaseq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Verlauf von PowerShell

Die Datei `ConsoleHost_history.txt` ist der PSReadLine-Verlauf von PowerShell. Sie enthält die Befehle, die die Zugangsdaten des Kontos `CORP\svc-ops` abfragen und eine Remote-Sitzung zu `serverq3xwz7a2kfm4ub6tyc5nre.d.example.net` öffnen. Der Host-Name gehört zu einem DNS-Honeytoken: Wer die Befehle ausführt oder sich sonst mit dem Server verbindet, löst ihn auf, was ein Event auslöst. Dahinter steht kein Server, und das Konto gibt es nirgends. Die Datei enthält kein Passwort: PowerShell schreibt keine Befehlszeilen mit Passwörtern in seinen Verlauf.

### Datei platzieren

1. Legen Sie die Datei als `ConsoleHost_history.txt` im Verzeichnis `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine` eines Kontos auf einem Server oder Arbeitsplatz von Administratoren ab.
2. Hat das Konto schon einen Verlauf, hängen Sie die Zeilen an, statt ihn zu ersetzen.
3. Halten Sie in den Platzierungsnotizen des Artefakts fest, wo Sie es abgelegt haben.

### Testen

Lösen Sie den Host mit `nslookup serverq3xwz7a2kfm4ub6tyc5nre.d.example.net` auf einem Rechner mit Zugang zum Internet auf. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Event aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert es.
- Die Host-Namen sind zufällige Labels unter der Zone Ihrer DNS-Rolle. Ein Eindringling, der die Dateien genau liest, kann sie ungewöhnlich finden.
- Das Lesen der Dateien löst kein Event aus; erst die Verwendung der Zugangsdaten oder das Ausführen der Befehle tut es.
- `ConsoleHost_history.txt`: PSReadLine schreibt keine Befehlszeilen mit Passwort, Token oder Secret in den Verlauf, ein PowerShell-Verlauf mit einem Passwort wäre also ungewöhnlich. Die Datei enthält deshalb Konto und Server, aber kein Passwort.
