## Geschichte

Legen Sie einen Export von Sicherungseinstellungen dort ab, wo ein Angreifer nach gespeicherten Zugangsdaten sucht. Die Datei `Settings.reg` nennt einen Sicherungsserver, das Konto `svc-backup` und ein Passwort. Der Servername gehört zu einem DNS-Honeytoken: Wer mit diesen Einstellungen den Server erreichen will, löst den Namen auf, und die Abfrage löst ein Ereignis aus. Hinter dem Namen steht kein Server, und Konto und Passwort gibt es nirgends.

## Umsetzung

1. Legen Sie das DNS-Honeytoken „Sicherungsserver“ an. Ersetzen Sie `Honeytoken-Domain` in der Datei durch seinen Namen.
2. Passen Sie Kontonamen und Passwort an das Namensschema Ihrer Umgebung an. Wenn Sie eine andere Sicherungssoftware einsetzen, benennen Sie den Schlüssel `BackupPro` und die Datei entsprechend um.
3. Legen Sie die Datei dort ab, wo ein Angreifer nach Einstellungen von Sicherungssoftware sucht: auf einem gesicherten Server, in einem Ordner mit IT-Dokumentation oder in einer Sicherung eines Benutzerprofils.
4. Importieren Sie die Datei nicht auf einem Rechner, den Sie nutzen. Der Import schreibt den Schlüssel in die Registry des importierenden Kontos.
5. Notieren Sie im Szenario, wo die Datei liegt.

## Testen

Führen Sie auf einem Rechner mit Internetzugang `nslookup Honeytoken-Domain` aus, mit dem Namen des Honeytokens statt des Platzhalters. Den Namen finden Sie in der Tabelle „Honeytokens dieses Szenarios“. Innerhalb einer Minute zeigt das Szenario einen Incident. Schließen Sie den Incident nach dem Test.

Erscheint kein Incident, prüfen Sie, ob der Rechner Namen über einen Resolver auflöst, der die DNS-Rolle von Nyktus erreicht (siehe „Grenzen“).

## Grenzen

- Nur eine Abfrage, die die DNS-Rolle von Nyktus erreicht, löst ein Ereignis aus. Ein Netz ohne Namensauflösung ins Internet oder ein Resolver, der aus seinem Cache antwortet, verhindert das.
- Der Servername ist ein zufälliges Label unter der Zone Ihrer DNS-Rolle. Wer die Datei genau liest, kann ihn ungewöhnlich finden.
- Der Import der Datei legt den Schlüssel an, startet aber nichts. Wer die Datei nur liest oder importiert, löst kein Ereignis aus; die Abfrage entsteht erst, wenn ein Programm sich mit dem Server verbindet.
